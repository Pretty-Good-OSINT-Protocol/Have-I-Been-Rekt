import { BrowserRouter as Router, Routes, Route, Link } from "react-router-dom";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import Home from "./views/Home";
import About from "./views/About";
import NotFound from "./views/NotFound";
import CompromisedWalletForm from "./views/CompromisedWalletForm";

function App() {
  return (
    <Router>
      <div className="min-h-screen min-w-screen bg-gray-900 text-gray-200">
        {/* Navigation Bar */}
        <nav className="bg-gray-800 shadow-lg">
          <div className="container mx-auto px-4 py-4 flex justify-between items-center">
            <h1 className="text-2xl font-bold text-pink-500">
              Have-I-Been-Rekt
            </h1>
            <ul className="flex space-x-6">
              <li>
                <Link
                  to="/"
                  className="text-gray-200 hover:text-pink-500 transition duration-300"
                >
                  Home
                </Link>
              </li>
              <li>
                <Link
                  to="/about"
                  className="text-gray-200 hover:text-pink-500 transition duration-300"
                >
                  About
                </Link>
              </li>
            </ul>
          </div>
        </nav>

        {/* Main Content */}
        <main className="container mx-auto px-4 py-8">
          <div className="bg-gray-800 p-6 rounded-lg shadow-lg">
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/about" element={<About />} />
              <Route path="/report" element={<CompromisedWalletForm />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </div>
        </main>

        {/* Toast Notifications */}
        <ToastContainer
          position="top-right"
          autoClose={3000}
          hideProgressBar={false}
          newestOnTop={false}
          closeOnClick
          rtl={false}
          pauseOnFocusLoss
          draggable
          pauseOnHover
          theme="dark"
        />
      </div>
    </Router>
  );
}

export default App;
