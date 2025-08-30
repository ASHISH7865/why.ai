import express from "express";
const router = express.Router();
router.get("/:id", () => {
    console.log("return specfic session data");
});
router.post("/", () => {
    console.log("sessions");
});
export default router;
