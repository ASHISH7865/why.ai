/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
import bcrypt from "bcryptjs";
import mongoose, { Schema, Document, Model, Types } from "mongoose";

export type MsgRole = "assistant" | "system" | "user";
export type Role = "admin" | "user";

//soft delete
function softDeletePlugin(schema: Schema) {
  schema.add({
    isDeleted: {
      default: false,
      index: true,
      type: Boolean,
    },
    deletedAt: { type: Date },
  });
  schema.methods.softDelete = async function () {
    this.isDeleted = true;
    this.deletedAt = new Date();
    await this.save();
  };
  schema.statics.findNotDeleted = function (cond = {}) {
    return this.find({ isDeleted: false, ...cond });
  };
}

// json cleanup
// toJSON cleanups
function toJSONPlugin(schema: Schema) {
  schema.set("toJSON", {
    virtuals: true,
    versionKey: false,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    transform: (_doc: any, ret: any) => {
      delete ret._id; // expose id instead
      return ret;
    },
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  schema.virtual("id").get(function (this: any) {
    return this._id.toString();
  });
}

export interface IUser extends Document {
  name: string;
  email: string;
  passwordHash: string;
  roles: Role[];
  lastLoginAt?: Date;
  isDeleted: boolean;
  deletedAt?: Date;
  comparePassword: (pw: string) => Promise<boolean>;
}

const UserSchema = new Schema<IUser>(
  {
    name: { type: String, trim: true, maxLength: 120, required: true },
    email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
      unique: true,
      index: true,
      validate: {
        validator: (v: string) => /.+@.+\..+/.test(v),
        message: "Invalid email",
      },
    },
    passwordHash: { type: String, required: true, select: false },
    roles: { type: [String], enum: ["user", "admin"], default: ["user"] },
    lastLoginAt: { type: Date },
  },
  { timestamps: true },
);

UserSchema.plugin(softDeletePlugin);
UserSchema.plugin(toJSONPlugin);

UserSchema.methods.comparePassword = async function (pw: string) {
  return bcrypt.compare(pw, this.passwordHash);
};

UserSchema.index({ email: 1, isDeleted: 1 });

export const User: Model<IUser> = mongoose.model<IUser>("User", UserSchema);

export interface ITopic extends Document {
  userId: Types.ObjectId;
  title: string;
  description?: string;
  rootMessageId?: Types.ObjectId; // first AI answer or starting message
  visibility: "private" | "unlisted" | "public";
  tags: string[];
  rootSummary: string; // short summary of the whole topic trajectory
  isDeleted: boolean;
  deletedAt?: Date;
}

const TopicSchema = new Schema<ITopic>(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", index: true, required: true },
    title: { type: String, required: true, trim: true, maxlength: 180 },
    description: { type: String, maxlength: 5000 },
    rootMessageId: { type: Schema.Types.ObjectId, ref: "Message" },
    visibility: { type: String, enum: ["private", "unlisted", "public"], default: "private", index: true },
    tags: { type: [String], index: true, default: [] },
    rootSummary: { type: String, default: "" },
  },
  { timestamps: true },
);

TopicSchema.plugin(softDeletePlugin);
TopicSchema.plugin(toJSONPlugin);

TopicSchema.index({ userId: 1, createdAt: -1 });
TopicSchema.index({ title: "text", description: "text", tags: "text" });

export const Topic: Model<ITopic> = mongoose.model<ITopic>("Topic", TopicSchema);

export interface IMessage extends Document {
  topicId: Types.ObjectId;
  parentMessageId?: Types.ObjectId | null; // tree linkage
  role: MsgRole;
  content: string;
  tokensIn?: number;
  tokensOut?: number;
  modelName?: string;
  latencyMs?: number;
  breadcrumb: string[];
  // Derived/virtuals
  children?: IMessage[];
  // Soft-delete
  isDeleted: boolean;
  deletedAt?: Date;
}

const MessageSchema = new Schema<IMessage>(
  {
    topicId: { type: Schema.Types.ObjectId, ref: "Topic", index: true, required: true },
    parentMessageId: { type: Schema.Types.ObjectId, ref: "Message", default: null, index: true },
    role: { type: String, enum: ["user", "assistant", "system"], required: true, index: true },
    content: { type: String, required: true },
    tokensIn: { type: Number, default: 0 },
    tokensOut: { type: Number, default: 0 },
    modelName: { type: String },
    latencyMs: { type: Number },
    breadcrumb: { type: [String], default: [] },
  },
  { timestamps: true },
);

MessageSchema.plugin(softDeletePlugin);
MessageSchema.plugin(toJSONPlugin);

MessageSchema.virtual("children", {
  ref: "Message",
  localField: "_id",
  foreignField: "parentMessageId",
  justOne: false,
});

MessageSchema.index({ topicId: 1, parentMessageId: 1, createdAt: 1 }); // pagination within a branch
MessageSchema.index({ topicId: 1, createdAt: 1 });
MessageSchema.index({ role: 1, createdAt: -1 });
MessageSchema.index({ content: "text" });

MessageSchema.statics.getThread = async function (rootMessageId: Types.ObjectId) {
  const all = await this.find({
    $or: [{ _id: rootMessageId }, { parentMessageId: rootMessageId }],
  });
  // NOTE: for large trees, switch to aggregation with $graphLookup
  return all;
};

// Method example to compute/update breadcrumb path labels
MessageSchema.methods.computeBreadcrumb = async function () {
  let cursor: IMessage | null = this as IMessage;
  const labels: string[] = [];
  while (cursor.parentMessageId) {
    const parent = await Message.findById(cursor.parentMessageId).lean();
    if (!parent) break;
    // Heuristic: take first 6 words of parent content as label
    const label = (parent.content || "").split(/\s+/).slice(0, 6).join(" ");
    labels.unshift(label);
    cursor = parent as IMessage;
  }
  this.breadcrumb = labels;
  return labels;
};

export const Message = mongoose.model<IMessage, Model<IMessage> & { getThread: (rootMessageId: Types.ObjectId) => Promise<IMessage[]> }>(
  "Message",
  MessageSchema,
);

export interface IHighlight extends Document {
  messageId: Types.ObjectId; // the message where text was highlighted
  text: string; // highlighted phrase (e.g., "Proof of Work")
  startOffset: number; // optional: character offset in content
  endOffset: number; // optional: character offset in content
  nestedMessageId?: Types.ObjectId; // optional: the first message of the nested deep dive
}

const HighlightSchema = new Schema<IHighlight>(
  {
    messageId: { type: Schema.Types.ObjectId, ref: "Message", index: true, required: true },
    text: { type: String, required: true, maxlength: 500 },
    startOffset: { type: Number, default: -1 },
    endOffset: { type: Number, default: -1 },
    nestedMessageId: { type: Schema.Types.ObjectId, ref: "Message", index: true },
  },
  { timestamps: true },
);

HighlightSchema.plugin(toJSONPlugin);
HighlightSchema.index({ messageId: 1, createdAt: -1 });

export const Highlight: Model<IHighlight> = mongoose.model<IHighlight>("Highlight", HighlightSchema);

export interface IContextCache extends Document {
  topicId: Types.ObjectId;
  nodeMessageId?: Types.ObjectId; // optional: cache per subtree root
  summary: string; // compact summary used in prompts
  lastMessageIds: Types.ObjectId[]; // a window of last N message ids
  // TTL maintenance
  expiresAt?: Date; // optional TTL index
}

const ContextCacheSchema = new Schema<IContextCache>(
  {
    topicId: { type: Schema.Types.ObjectId, ref: "Topic", index: true, required: true },
    nodeMessageId: { type: Schema.Types.ObjectId, ref: "Message", index: true },
    summary: { type: String, default: "" },
    lastMessageIds: { type: [Schema.Types.ObjectId], default: [] },
    expiresAt: { type: Date, index: { expireAfterSeconds: 0 }, default: undefined }, // set to enable TTL
  },
  { timestamps: true },
);

ContextCacheSchema.plugin(toJSONPlugin);
ContextCacheSchema.index({ topicId: 1, nodeMessageId: 1 }, { unique: true, partialFilterExpression: { nodeMessageId: { $type: "objectId" } } });

export const ContextCache: Model<IContextCache> = mongoose.model<IContextCache>("ContextCache", ContextCacheSchema);

TopicSchema.pre("save", function (next) {
  next();
});

TopicSchema.post("findOneAndUpdate", async function (doc: ITopic) {
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
  if (!doc) return;
  if (doc.isDeleted) {
    await Message.updateMany({ topicId: doc._id, isDeleted: false }, { isDeleted: true, deletedAt: new Date() });
    const msgs = await Message.find({ topicId: doc._id }).select("_id");
    await Highlight.deleteMany({ messageId: { $in: msgs.map((m) => m._id) } });
    await ContextCache.deleteMany({ topicId: doc._id });
  }
});

MessageSchema.path("content").validate(function (v: string) {
  return v && v.trim().length > 0;
}, "Message content required");

export async function createUserSecure(name: string, email: string, password: string) {
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);
  return User.create({ name, email, passwordHash });
}

// Example: Efficiently fetch a message with children count and recent children
export async function getMessageWithChildren(messageId: string, limit = 10) {
  const [doc] = await Message.aggregate([
    { $match: { _id: new Types.ObjectId(messageId), isDeleted: false } },
    { $lookup: { from: "messages", localField: "_id", foreignField: "parentMessageId", as: "children" } },
    { $addFields: { childrenCount: { $size: "$children" }, recentChildren: { $slice: ["$children", -limit] } } },
    { $project: { children: 0 } },
  ]);
  return doc;
}

export default { User, Topic, Message, Highlight, ContextCache };
