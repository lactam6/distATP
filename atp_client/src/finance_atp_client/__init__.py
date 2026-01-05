"""FinanceATP API Client - ATP通貨管理APIのGUIクライアント"""

import tkinter as tk

__version__ = "1.0.0"
__all__ = ["FinanceATPClient", "main"]

# Import the client class
from .client import FinanceATPClient


def main():
    """atp-client コマンドのエントリポイント"""
    root = tk.Tk()
    app = FinanceATPClient(root)
    root.mainloop()
