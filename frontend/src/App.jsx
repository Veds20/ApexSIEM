import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";

import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Priority from "./pages/Priority";
import Investigations from "./pages/Investigations";
import ProtectedRoute from "./components/ProtectedRoute";

export default function App() {
    return (
        <BrowserRouter>
            <Routes>
                {/* Public */}
                <Route path="/" element={<Login />} />

                {/* Protected */}
                <Route path="/dashboard" element={
                    <ProtectedRoute><Dashboard /></ProtectedRoute>
                } />
                <Route path="/priority" element={
                    <ProtectedRoute><Priority /></ProtectedRoute>
                } />
                <Route path="/investigations" element={
                    <ProtectedRoute><Investigations /></ProtectedRoute>
                } />

                {/* Catch-all → login */}
                <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
        </BrowserRouter>
    );
}