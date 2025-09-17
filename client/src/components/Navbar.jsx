import React from "react";
import { assets } from "../assets/assets";

const navbar = () => {
  return (
    <div>
      <img src="{assets.logo}" alt="" className="w-28 sm:w-32" />
      <button>Login</button>
    </div>
  );
};

export default navbar;
