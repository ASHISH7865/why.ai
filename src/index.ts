import express from "express";
import helmet from "helmet";

import sessionRouter from "@/routes/session.routes.js";

const app = express();
const port = process.env.PORT ?? "9001";

// middlewares
app.use(helmet());

app.get("/healthz", (_req, res) => {
  console.log("called");
  res.json({
    message: "OK",
  });
});

app.use("/api/sessions", sessionRouter);

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
