import React from "react";
import { assets } from "../assets/assets.js";

const Navbar = () => {
  return (
    <div>
      <img
        src="{assets.logo}"
        alt="Authenticate Logo"
        className="w-28 sm:w-32"
      />
      <button>Login</button>
    </div>
  );
};

export default Navbar;
