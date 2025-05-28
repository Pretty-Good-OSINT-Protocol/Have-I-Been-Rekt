import React from "react";
import { useNavigate } from "react-router-dom";

const Home: React.FC = () => {
  const navigate = useNavigate();

  const handleReportClick = () => {
    navigate("/report"); // Navigate to the form page
  };

  return (
    <div className="text-center space-y-6">
      <h1 className="text-4xl font-bold text-pink-500">
        Welcome to Have-I-Been-Rekt
      </h1>
      <p className="text-lg text-gray-300">
        If you suspect your wallet has been compromised, click the button below
        to report it.
      </p>
      <button
        onClick={handleReportClick}
        className="px-6 py-3 bg-pink-500 text-white font-semibold rounded-lg shadow-md hover:bg-pink-600 transition duration-300"
      >
        Report Compromised Wallet
      </button>
    </div>
  );
};

export default Home;
