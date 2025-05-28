import React from "react";
import { Link } from "react-router-dom";

const NotFound: React.FC = () => {
  return (
    <div className="text-center">
      <h1 className="text-4xl font-bold text-red-600">404</h1>
      <p className="text-lg">Page not found</p>
      <Link to="/" className="text-blue-500 hover:underline">
        Go back to Home
      </Link>
    </div>
  );
};

export default NotFound;
