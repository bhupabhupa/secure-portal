import React from "react";
import { createRoot } from "react-dom/client";
import { initAuth } from "./keycloak.js";
import App from "./App.jsx";

// Authenticate FIRST, render after — no flash of unauthenticated UI.
initAuth().then(() => {
  createRoot(document.getElementById("root")).render(<App />);
});
