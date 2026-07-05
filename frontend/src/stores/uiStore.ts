import { create } from "zustand";

type SidebarState = "expanded" | "collapsed";

interface UiState {
  sidebar: SidebarState;
  theme: "dark" | "light";
  toggleSidebar: () => void;
  setSidebar: (state: SidebarState) => void;
}

export const useUiStore = create<UiState>((set) => ({
  sidebar: "expanded",
  theme: "dark",
  toggleSidebar: () =>
    set((state) => ({
      sidebar: state.sidebar === "expanded" ? "collapsed" : "expanded",
    })),
  setSidebar: (sidebar: SidebarState) => set({ sidebar }),
}));
