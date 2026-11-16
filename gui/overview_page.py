"""Overview: the workbench's home page.

It will hold the interactive topology canvas (the next step). Until that canvas
is built and tested, this page is a clearly labelled placeholder: it shows no
statistics and no network data, only the way to the current map.
"""
import tkinter as tk

import customtkinter as ctk

from gui import theme


class OverviewPage(tk.Frame):
    def __init__(self, parent, open_page):
        """open_page(key) switches to another page."""
        super().__init__(parent, background=theme.SURFACE)
        self.open_page = open_page

        head = tk.Frame(self, background=theme.SURFACE)
        head.pack(fill='x', padx=14, pady=(10, 6))
        tk.Label(head, text='Overview', font=theme.FONT_TITLE, background=theme.SURFACE,
                 foreground=theme.TEXT).pack(side='left')

        area = tk.Frame(self, background=theme.CANVAS_BG, highlightthickness=1,
                        highlightbackground=theme.BORDER)
        area.pack(fill='both', expand=True, padx=14, pady=(0, 14))
        inner = tk.Frame(area, background=theme.CANVAS_BG)
        inner.place(relx=0.5, rely=0.45, anchor='center')
        tk.Label(inner, text='PLACEHOLDER', font=theme.mono(9, 'bold'), background=theme.CANVAS_BG,
                 foreground=theme.TEXT_MUTED).pack()
        tk.Label(inner, text='Interactive topology workspace', font=theme.FONT_TITLE,
                 background=theme.CANVAS_BG, foreground=theme.TEXT).pack(pady=(4, 2))
        self.message = tk.Label(
            inner, background=theme.CANVAS_BG, foreground=theme.TEXT_SOFT, font=theme.FONT,
            justify='center',
            text='The clickable network map will be built here in a later step.\n'
                 'The current map is on the Topology page.')
        self.message.pack()
        self.open_topology = ctk.CTkButton(
            inner, text='Open Topology', height=30, corner_radius=3, font=theme.FONT_BOLD,
            fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER,
            command=lambda: self.open_page('topology'))
        self.open_topology.pack(pady=(12, 0))

    def refresh(self):
        """Called each time the page is shown (nothing to load yet)."""
