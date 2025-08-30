import bcrypt from "bcryptjs";
import mongoose, { Schema, Types } from "mongoose";
//soft delete
function softDeletePlugin(schema) {
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
function toJSONPlugin(schema) {
    schema.set("toJSON", {
        virtuals: true,
        versionKey: false,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        transform: (_doc, ret) => {
            delete ret._id; // expose id instead
            return ret;
        },
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    schema.virtual("id").get(function () {
        return this._id.toString();
    });
}
const UserSchema = new Schema({
    name: { type: String, trim: true, maxLength: 120, required: true },
    email: {
        type: String,
        required: true,
        lowercase: true,
        trim: true,
        unique: true,
        index: true,
        validate: {
            validator: (v) => /.+@.+\..+/.test(v),
            message: "Invalid email",
        },
    },
    passwordHash: { type: String, required: true, select: false },
    roles: { type: [String], enum: ["user", "admin"], default: ["user"] },
    lastLoginAt: { type: Date },
}, { timestamps: true });
UserSchema.plugin(softDeletePlugin);
UserSchema.plugin(toJSONPlugin);
UserSchema.methods.comparePassword = async function (pw) {
    return bcrypt.compare(pw, this.passwordHash);
};
UserSchema.index({ email: 1, isDeleted: 1 });
export const User = mongoose.model("User", UserSchema);
const TopicSchema = new Schema({
    userId: { type: Schema.Types.ObjectId, ref: "User", index: true, required: true },
    title: { type: String, required: true, trim: true, maxlength: 180 },
    description: { type: String, maxlength: 5000 },
    rootMessageId: { type: Schema.Types.ObjectId, ref: "Message" },
    visibility: { type: String, enum: ["private", "unlisted", "public"], default: "private", index: true },
    tags: { type: [String], index: true, default: [] },
    rootSummary: { type: String, default: "" },
}, { timestamps: true });
TopicSchema.plugin(softDeletePlugin);
TopicSchema.plugin(toJSONPlugin);
TopicSchema.index({ userId: 1, createdAt: -1 });
TopicSchema.index({ title: "text", description: "text", tags: "text" });
export const Topic = mongoose.model("Topic", TopicSchema);
const MessageSchema = new Schema({
    topicId: { type: Schema.Types.ObjectId, ref: "Topic", index: true, required: true },
    parentMessageId: { type: Schema.Types.ObjectId, ref: "Message", default: null, index: true },
    role: { type: String, enum: ["user", "assistant", "system"], required: true, index: true },
    content: { type: String, required: true },
    tokensIn: { type: Number, default: 0 },
    tokensOut: { type: Number, default: 0 },
    modelName: { type: String },
    latencyMs: { type: Number },
    breadcrumb: { type: [String], default: [] },
}, { timestamps: true });
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
MessageSchema.statics.getThread = async function (rootMessageId) {
    const all = await this.find({
        $or: [{ _id: rootMessageId }, { parentMessageId: rootMessageId }],
    });
    // NOTE: for large trees, switch to aggregation with $graphLookup
    return all;
};
// Method example to compute/update breadcrumb path labels
MessageSchema.methods.computeBreadcrumb = async function () {
    let cursor = this;
    const labels = [];
    while (cursor.parentMessageId) {
        const parent = await Message.findById(cursor.parentMessageId).lean();
        if (!parent)
            break;
        // Heuristic: take first 6 words of parent content as label
        const label = (parent.content || "").split(/\s+/).slice(0, 6).join(" ");
        labels.unshift(label);
        cursor = parent;
    }
    this.breadcrumb = labels;
    return labels;
};
export const Message = mongoose.model("Message", MessageSchema);
const HighlightSchema = new Schema({
    messageId: { type: Schema.Types.ObjectId, ref: "Message", index: true, required: true },
    text: { type: String, required: true, maxlength: 500 },
    startOffset: { type: Number, default: -1 },
    endOffset: { type: Number, default: -1 },
    nestedMessageId: { type: Schema.Types.ObjectId, ref: "Message", index: true },
}, { timestamps: true });
HighlightSchema.plugin(toJSONPlugin);
HighlightSchema.index({ messageId: 1, createdAt: -1 });
export const Highlight = mongoose.model("Highlight", HighlightSchema);
const ContextCacheSchema = new Schema({
    topicId: { type: Schema.Types.ObjectId, ref: "Topic", index: true, required: true },
    nodeMessageId: { type: Schema.Types.ObjectId, ref: "Message", index: true },
    summary: { type: String, default: "" },
    lastMessageIds: { type: [Schema.Types.ObjectId], default: [] },
    expiresAt: { type: Date, index: { expireAfterSeconds: 0 }, default: undefined }, // set to enable TTL
}, { timestamps: true });
ContextCacheSchema.plugin(toJSONPlugin);
ContextCacheSchema.index({ topicId: 1, nodeMessageId: 1 }, { unique: true, partialFilterExpression: { nodeMessageId: { $type: "objectId" } } });
export const ContextCache = mongoose.model("ContextCache", ContextCacheSchema);
TopicSchema.pre("save", function (next) {
    next();
});
TopicSchema.post("findOneAndUpdate", async function (doc) {
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
    if (!doc)
        return;
    if (doc.isDeleted) {
        await Message.updateMany({ topicId: doc._id, isDeleted: false }, { isDeleted: true, deletedAt: new Date() });
        const msgs = await Message.find({ topicId: doc._id }).select("_id");
        await Highlight.deleteMany({ messageId: { $in: msgs.map((m) => m._id) } });
        await ContextCache.deleteMany({ topicId: doc._id });
    }
});
MessageSchema.path("content").validate(function (v) {
    return v && v.trim().length > 0;
}, "Message content required");
export async function createUserSecure(name, email, password) {
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);
    return User.create({ name, email, passwordHash });
}
// Example: Efficiently fetch a message with children count and recent children
export async function getMessageWithChildren(messageId, limit = 10) {
    const [doc] = await Message.aggregate([
        { $match: { _id: new Types.ObjectId(messageId), isDeleted: false } },
        { $lookup: { from: "messages", localField: "_id", foreignField: "parentMessageId", as: "children" } },
        { $addFields: { childrenCount: { $size: "$children" }, recentChildren: { $slice: ["$children", -limit] } } },
        { $project: { children: 0 } },
    ]);
    return doc;
}
export default { User, Topic, Message, Highlight, ContextCache };
