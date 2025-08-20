import { Router } from "express";
import { authMiddleware } from "../middlewares/authMiddleware";
import { authorizeRoles } from "../middlewares/roleMiddleware";

const router = Router();

router.get("/dashboard", authMiddleware, authorizeRoles("admin"), (req, res) => {
  res.json({ message: "Welcome Admin Dashboard" });
});

export default router;
