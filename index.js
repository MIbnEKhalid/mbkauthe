import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import { engine } from "express-handlebars";
import compression from "compression";
import mbkAuthRouter from "mbkauthe";
import { validateSession, checkRolePermission, validateSessionAndRole, getUserData } from "mbkauthe";

dotenv.config();
const app = express();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const router = app;

router.use(express.json());  // <--- Move express.json() to be first
router.use(mbkAuthRouter);   // <--- Keep mbkAuthRouter after express.json()

router.use(compression());
// Configure Handlebars
router.engine("handlebars", engine({
    defaultLayout: false,
    partialsDir: [
        path.join(__dirname, "views/templates"),
        path.join(__dirname, "views/notice"),
        path.join(__dirname, "views")
    ],
    cache: false,
    helpers: { // <-- ADD THIS helpers OBJECT
        eq: function (a, b) { // <-- Move your helpers inside here
            return a === b;
        },
        encodeURIComponent: function (str) {
            return encodeURIComponent(str);
        },
        formatTimestamp: function (timestamp) {
            return new Date(timestamp).toLocaleString();
        },
        jsonStringify: function (context) {
            return JSON.stringify(context);
        }
    }
}));

router.set("view engine", "handlebars");
router.set("views", path.join(__dirname, "views"));

// Serve static files
router.use(
  "/Assets",
  express.static(path.join(__dirname, "public/Assets"), {
    setHeaders: (res, path) => {
      if (path.endsWith(".css")) {
        res.setHeader("Content-Type", "text/css");
      }
    },
  })
);

router.use(mbkAuthRouter);


router.get(["/login", "/signin","/"], (req, res) => {
  if (req.session && req.session.user) {
    return res.render("mainPages/login.handlebars", { userLoggedIn: true, UserName: req.session.user.username });
  }
  return res.render("mainPages/login.handlebars");
});

// Require vaild session or to be login to access this page
router.get(["/home"],validateSession, (req, res) => {
    return res.status(200).render("mainPages/home", { userLoggedIn: true, UserName: req.session.user.username });
  
}); 

const port = 3130;

// Start the router
router.listen(port, () => {
  console.log(`router running on http://localhost:${port}`);
});
export default router;