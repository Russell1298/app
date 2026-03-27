import { useState, useEffect } from "react";

interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: { name: string; email: string } | null;
}

export function useAuth(): AuthState {
  const [state, setState] = useState<AuthState>({
    isAuthenticated: false,
    isLoading: true,
    user: null
  });

  useEffect(() => {
    // Simulate checking persisted session
    const timer = setTimeout(() => {
      setState({ isAuthenticated: false, isLoading: false, user: null });
    }, 500);
    return () => clearTimeout(timer);
  }, []);

  return state;
}
