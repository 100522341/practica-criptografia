"""
Interfaz gráfica principal (Tkinter) para la gestión de un hotel.
Solo UI; sin lógica de negocio ni persistencia.
"""

import tkinter as tk
from tkinter import ttk, messagebox


class HotelUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()

        # Ventana principal
        self.title("Hotel — Gestión de Reservas")
        self.geometry("1100x720")
        self.minsize(900, 600)
        self.option_add("*tearOff", False)

        # Tema/estilo
        style = ttk.Style(self)
        themes = style.theme_names()
        if "vista" in themes:
            style.theme_use("vista")
        elif "clam" in themes:
            style.theme_use("clam")

        # Disposición base
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        self._build_menu()
        self._build_toolbar()
        self._build_main_tabs()
        self._build_statusbar()

        self.bind("<F5>", lambda e: self.on_actualizar())
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

    # Menú superior
    def _build_menu(self) -> None:
        menubar = tk.Menu(self)

        menu_archivo = tk.Menu(menubar)
        menu_archivo.add_command(label="Nueva reserva", command=self.on_nueva_reserva)
        menu_archivo.add_separator()
        menu_archivo.add_command(label="Salir", command=self.quit)

        menu_ayuda = tk.Menu(menubar)
        menu_ayuda.add_command(label="Acerca de", command=self._show_about)

        menubar.add_cascade(label="Archivo", menu=menu_archivo)
        menubar.add_cascade(label="Ayuda", menu=menu_ayuda)
        self.config(menu=menubar)

    # Barra de herramientas
    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self, padding=(10, 6))
        bar.grid(row=0, column=0, sticky="ew")
        bar.columnconfigure(10, weight=1)

        btn_specs = [
            ("Nueva reserva", self.on_nueva_reserva),
            ("Check‑in", self.on_check_in),
            ("Check‑out", self.on_check_out),
            ("Cancelar", self.on_cancelar),
            ("Actualizar", self.on_actualizar),
        ]
        for i, (text, cmd) in enumerate(btn_specs):
            ttk.Button(bar, text=text, command=cmd).grid(row=0, column=i, padx=(0 if i else 0, 8))

        # Espaciador flexible
        ttk.Label(bar, text="").grid(row=0, column=10, sticky="ew")

    # Área principal con pestañas
    def _build_main_tabs(self) -> None:
        nb = ttk.Notebook(self)
        nb.grid(row=1, column=0, sticky="nsew")
        self.notebook = nb

        self.tab_reservas = self._make_tab_reservas(nb)
        self.tab_clientes = self._make_tab_clientes(nb)
        self.tab_habitaciones = self._make_tab_habitaciones(nb)

        nb.add(self.tab_reservas, text="Reservas")
        nb.add(self.tab_clientes, text="Clientes")
        nb.add(self.tab_habitaciones, text="Habitaciones")

    def _build_statusbar(self) -> None:
        status = ttk.Frame(self, padding=(10, 4))
        status.grid(row=2, column=0, sticky="ew")
        status.columnconfigure(0, weight=1)
        self.status_var = tk.StringVar(value="Listo")
        ttk.Label(status, textvariable=self.status_var, anchor="w").grid(row=0, column=0, sticky="ew")

    # -------------------------- Pestaña: Reservas --------------------------
    def _make_tab_reservas(self, parent: tk.Misc) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=10)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

        filtro = ttk.Frame(frame)
        filtro.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        filtro.columnconfigure(1, weight=1)

        ttk.Label(filtro, text="Buscar:").grid(row=0, column=0, padx=(0, 8))
        self.busqueda_reservas = tk.StringVar()
        ttk.Entry(filtro, textvariable=self.busqueda_reservas).grid(row=0, column=1, sticky="ew", padx=(0, 8))
        ttk.Button(filtro, text="Buscar", command=self.on_buscar_reservas).grid(row=0, column=2)
        ttk.Button(filtro, text="Limpiar", command=lambda: self._clear_entry(self.busqueda_reservas)).grid(row=0, column=3, padx=(8, 0))

        lista = ttk.Frame(frame)
        lista.grid(row=1, column=0, sticky="nsew")
        lista.rowconfigure(0, weight=1)
        lista.columnconfigure(0, weight=1)

        cols = ("id", "cliente", "hab", "entrada", "salida", "estado")
        tree = ttk.Treeview(lista, columns=cols, show="headings", selectmode="browse")
        self.tree_reservas = tree
        tree.heading("id", text="ID")
        tree.heading("cliente", text="Cliente")
        tree.heading("hab", text="Habitación")
        tree.heading("entrada", text="Entrada")
        tree.heading("salida", text="Salida")
        tree.heading("estado", text="Estado")

        tree.column("id", width=70, anchor="center")
        tree.column("cliente", width=200)
        tree.column("hab", width=110, anchor="center")
        tree.column("entrada", width=120, anchor="center")
        tree.column("salida", width=120, anchor="center")
        tree.column("estado", width=110, anchor="center")

        yscroll = ttk.Scrollbar(lista, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=yscroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")

        demo = [
            ("R-001", "Ana Pérez", "101", "2025-10-10", "2025-10-12", "Confirmada"),
            ("R-002", "Luis García", "203", "2025-10-11", "2025-10-14", "Check‑in"),
            ("R-003", "María López", "305", "2025-10-20", "2025-10-23", "Pendiente"),
        ]
        for row in demo:
            tree.insert("", "end", values=row)

        tree.bind("<Double-1>", lambda e: self._show_detalle("reserva"))
        return frame

    # -------------------------- Pestaña: Clientes --------------------------
    def _make_tab_clientes(self, parent: tk.Misc) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=10)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

        filtro = ttk.Frame(frame)
        filtro.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        filtro.columnconfigure(1, weight=1)

        ttk.Label(filtro, text="Buscar:").grid(row=0, column=0, padx=(0, 8))
        self.busqueda_clientes = tk.StringVar()
        ttk.Entry(filtro, textvariable=self.busqueda_clientes).grid(row=0, column=1, sticky="ew", padx=(0, 8))
        ttk.Button(filtro, text="Buscar", command=self.on_buscar_clientes).grid(row=0, column=2)
        ttk.Button(filtro, text="Limpiar", command=lambda: self._clear_entry(self.busqueda_clientes)).grid(row=0, column=3, padx=(8, 0))

        lista = ttk.Frame(frame)
        lista.grid(row=1, column=0, sticky="nsew")
        lista.rowconfigure(0, weight=1)
        lista.columnconfigure(0, weight=1)

        cols = ("id", "nombre", "dni", "telefono", "email")
        tree = ttk.Treeview(lista, columns=cols, show="headings", selectmode="browse")
        self.tree_clientes = tree
        tree.heading("id", text="ID")
        tree.heading("nombre", text="Nombre")
        tree.heading("dni", text="DNI")
        tree.heading("telefono", text="Teléfono")
        tree.heading("email", text="Email")

        tree.column("id", width=70, anchor="center")
        tree.column("nombre", width=220)
        tree.column("dni", width=120, anchor="center")
        tree.column("telefono", width=140, anchor="center")
        tree.column("email", width=220)

        yscroll = ttk.Scrollbar(lista, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=yscroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")

        demo = [
            ("C-001", "Ana Pérez", "12345678A", "+34 600 111 222", "ana@example.com"),
            ("C-002", "Luis García", "87654321B", "+34 600 333 444", "luis@example.com"),
            ("C-003", "María López", "11223344C", "+34 600 555 666", "maria@example.com"),
        ]
        for row in demo:
            tree.insert("", "end", values=row)

        tree.bind("<Double-1>", lambda e: self._show_detalle("cliente"))
        return frame

    # ----------------------- Pestaña: Habitaciones -------------------------
    def _make_tab_habitaciones(self, parent: tk.Misc) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=10)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

        filtro = ttk.Frame(frame)
        filtro.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        filtro.columnconfigure(1, weight=1)

        ttk.Label(filtro, text="Buscar:").grid(row=0, column=0, padx=(0, 8))
        self.busqueda_habs = tk.StringVar()
        ttk.Entry(filtro, textvariable=self.busqueda_habs).grid(row=0, column=1, sticky="ew", padx=(0, 8))
        ttk.Button(filtro, text="Buscar", command=self.on_buscar_habitaciones).grid(row=0, column=2)
        ttk.Button(filtro, text="Limpiar", command=lambda: self._clear_entry(self.busqueda_habs)).grid(row=0, column=3, padx=(8, 0))

        lista = ttk.Frame(frame)
        lista.grid(row=1, column=0, sticky="nsew")
        lista.rowconfigure(0, weight=1)
        lista.columnconfigure(0, weight=1)

        cols = ("numero", "tipo", "cap", "precio", "estado")
        tree = ttk.Treeview(lista, columns=cols, show="headings", selectmode="browse")
        self.tree_habs = tree
        tree.heading("numero", text="Nº")
        tree.heading("tipo", text="Tipo")
        tree.heading("cap", text="Capacidad")
        tree.heading("precio", text="Precio/Noche")
        tree.heading("estado", text="Estado")

        tree.column("numero", width=80, anchor="center")
        tree.column("tipo", width=150)
        tree.column("cap", width=110, anchor="center")
        tree.column("precio", width=130, anchor="center")
        tree.column("estado", width=120, anchor="center")

        yscroll = ttk.Scrollbar(lista, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=yscroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")

        demo = [
            ("101", "Individual", 1, "60.00 €", "Libre"),
            ("203", "Doble", 2, "85.00 €", "Ocupada"),
            ("305", "Suite", 3, "150.00 €", "Limpieza"),
        ]
        for row in demo:
            tree.insert("", "end", values=row)

        tree.bind("<Double-1>", lambda e: self._show_detalle("habitación"))
        return frame

    # ------------------------------ Acciones -------------------------------
    def on_nueva_reserva(self) -> None:
        messagebox.showinfo("Nueva reserva", "Pendiente de implementar.")

    def on_check_in(self) -> None:
        messagebox.showinfo("Check‑in", "Pendiente de implementar.")

    def on_check_out(self) -> None:
        messagebox.showinfo("Check‑out", "Pendiente de implementar.")

    def on_cancelar(self) -> None:
        messagebox.showinfo("Cancelar", "Pendiente de implementar.")

    def on_actualizar(self) -> None:
        self._set_status("Actualizado")

    def on_buscar_reservas(self) -> None:
        self._set_status(f"Buscar reservas: '{self.busqueda_reservas.get().strip()}'")

    def on_buscar_clientes(self) -> None:
        self._set_status(f"Buscar clientes: '{self.busqueda_clientes.get().strip()}'")

    def on_buscar_habitaciones(self) -> None:
        self._set_status(f"Buscar habitaciones: '{self.busqueda_habs.get().strip()}'")

    # --------------------------- Utilidades UI -----------------------------
    def _clear_entry(self, var: tk.StringVar) -> None:
        var.set("")
        self._set_status("Filtro limpiado")

    def _set_status(self, text: str) -> None:
        self.status_var.set(text)

    def _show_about(self) -> None:
        messagebox.showinfo(
            "Acerca de",
            "Gestión de Hotel — Interfaz de ejemplo\n"
            "Tkinter/ttk — Solo UI (sin lógica)",
        )

    def _show_detalle(self, tipo: str) -> None:
        messagebox.showinfo("Detalle", f"Abrir detalle de {tipo} (pendiente).")

    def _on_tab_changed(self, _event=None) -> None:
        idx = self.notebook.index("current")
        nombre = self.notebook.tab(idx, "text")
        self._set_status(f"Pestaña: {nombre}")


if __name__ == "__main__":
    app = HotelUI()
    app.mainloop()

