import tkinter as tk
from tkinter import messagebox, simpledialog

usuarios = {}
clientes = []
administrador = None  # Guarda o usuário admin com senha

PALAVRA_CHAVE_ADMIN = "Bala"  # Altere para sua palavra-chave secreta

def validar_login(usuario, senha):
    if usuario in usuarios and usuarios[usuario]["senha"] == senha:
        return usuarios[usuario]  # retorna dict do usuário (com flag admin)
    return None

def cadastrar_usuario(usuario, cpf, senha):
    if usuario in usuarios:
        return False
    usuarios[usuario] = {"cpf": cpf, "senha": senha, "admin": False}
    return True

def cadastrar_admin(usuario, senha):
    global administrador
    if administrador is not None:
        return False
    administrador = {"usuario": usuario, "senha": senha}
    usuarios[usuario] = {"cpf": "", "senha": senha, "admin": True}
    return True

def cadastrar_cliente(nome, cpf, telefone, email):
    clientes.append({"nome": nome, "cpf": cpf, "telefone": telefone, "email": email})

def buscar_cliente_por_cpf(cpf):
    for cliente in clientes:
        if cliente["cpf"] == cpf:
            return cliente
    return None

def remover_cliente(index):
    if 0 <= index < len(clientes):
        del clientes[index]

def on_entry_focus_in(event, entry, placeholder):
    if entry.get() == placeholder:
        entry.delete(0, "end")
        entry.config(fg="black")
        if "senha" in placeholder.lower():
            entry.config(show="*")

def on_entry_focus_out(event, entry, placeholder):
    if entry.get() == "":
        entry.insert(0, placeholder)
        entry.config(fg="grey")
        if "senha" in placeholder.lower():
            entry.config(show="")

def formatar_cpf(event, entry):
    texto = entry.get()
    texto = ''.join(filter(str.isdigit, texto))
    novo_texto = ""
    for i, digito in enumerate(texto):
        if i == 3 or i == 6:
            novo_texto += '.'
        if i == 9:
            novo_texto += '-'
        novo_texto += digito
    entry.delete(0, "end")
    entry.insert(0, novo_texto[:14])

def bind_enter_to_button(entry, button):
    entry.bind('<Return>', lambda e: button.invoke())

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("FinanMais Soluções Digitais")
        self.root.geometry("600x600")
        self.root.configure(bg="#e6f2ff")
        self.root.resizable(False, False)

        self.usuario_logado = None
        self.admin_logado = False

        self.frames = {}
        for F in (LoginPage, NovoUsuarioPage, NovoAdminPage, MenuPage, CadastroClientePage, ListaClientesPage, BuscarCpfPage):
            frame = F(self.root, self)
            self.frames[F.__name__] = frame

        self.show_frame("LoginPage")

    def show_frame(self, name):
        frame = self.frames[name]
        if name == "ListaClientesPage":
            frame.update_list()
        frame.tkraise()

class BasePage(tk.Frame):
    def __init__(self, root, controller):
        super().__init__(root, bg="#e6f2ff")
        self.controller = controller
        self.place(relx=0.5, rely=0.5, anchor="center", width=400, height=400)

class LoginPage(BasePage):
    def __init__(self, root, controller):
        super().__init__(root, controller)

        container = tk.Frame(self, bg="white", bd=2, relief="ridge")
        container.pack(expand=True, fill="both", padx=20, pady=20)

        tk.Label(container, text="Login", font=("Arial", 20, "bold"), bg="white").pack(pady=(20, 10))

        tk.Label(container, text="Usuário", bg="white", anchor="w").pack(fill="x", padx=30)
        self.usuario = tk.Entry(container, fg="grey")
        self.usuario.insert(0, "Usuário")
        self.usuario.bind("<FocusIn>", lambda e: on_entry_focus_in(e, self.usuario, "Usuário"))
        self.usuario.bind("<FocusOut>", lambda e: on_entry_focus_out(e, self.usuario, "Usuário"))
        self.usuario.pack(fill="x", padx=30, pady=5)

        tk.Label(container, text="Senha", bg="white", anchor="w").pack(fill="x", padx=30)
        self.senha = tk.Entry(container, fg="grey", show="")
        self.senha.insert(0, "Senha")
        self.senha.bind("<FocusIn>", lambda e: on_entry_focus_in(e, self.senha, "Senha"))
        self.senha.bind("<FocusOut>", lambda e: on_entry_focus_out(e, self.senha, "Senha"))
        self.senha.pack(fill="x", padx=30, pady=5)

        btn_entrar = tk.Button(container, text="Entrar", bg="#4CAF50", fg="white", command=self.login)
        btn_entrar.pack(fill="x", padx=30, pady=(10, 5))

        btn_novo = tk.Button(container, text="Novo Cadastro", bg="#2196F3", fg="white", command=lambda: controller.show_frame("NovoUsuarioPage"))
        btn_novo.pack(fill="x", padx=30, pady=(0,5))

        btn_admin = tk.Button(container, text="Criar Conta Admin", bg="#f44336", fg="white", command=lambda: controller.show_frame("NovoAdminPage"), width=20)
        btn_admin.pack(pady=(5, 0))

        bind_enter_to_button(self.usuario, btn_entrar)
        bind_enter_to_button(self.senha, btn_entrar)

    def login(self):
        user = self.usuario.get()
        pwd = self.senha.get()
        if user == "Usuário" or pwd == "Senha":
            messagebox.showerror("Erro", "Preencha usuário e senha")
            return
        dados_usuario = validar_login(user, pwd)
        if dados_usuario:
            self.controller.usuario_logado = user
            self.controller.admin_logado = dados_usuario.get("admin", False)
            self.controller.show_frame("MenuPage")
        else:
            messagebox.showerror("Erro", "Usuário ou senha inválidos")

class NovoUsuarioPage(BasePage):
    def __init__(self, root, controller):
        super().__init__(root, controller)
        tk.Label(self, text="Cadastro de Usuário", font=("Arial", 16), bg="#e6f2ff").pack(pady=10)

        self.entry_usuario = tk.Entry(self, fg="grey")
        self.entry_usuario.insert(0, "Usuário")
        self.entry_usuario.bind("<FocusIn>", lambda e: on_entry_focus_in(e, self.entry_usuario, "Usuário"))
        self.entry_usuario.bind("<FocusOut>", lambda e: on_entry_focus_out(e, self.entry_usuario, "Usuário"))
        self.entry_usuario.pack(pady=5)

        self.entry_cpf = tk.Entry(self, fg="grey")
        self.entry_cpf.insert(0, "CPF")
        self.entry_cpf.bind("<FocusIn>", lambda e: on_entry_focus_in(e, self.entry_cpf, "CPF"))
        self.entry_cpf.bind("<FocusOut>", lambda e: on_entry_focus_out(e, self.entry_cpf, "CPF"))
        self.entry_cpf.bind('<KeyRelease>', lambda e: formatar_cpf(e, self.entry_cpf))
        self.entry_cpf.pack(pady=5)

        self.entry_senha = tk.Entry(self, fg="grey", show="")
        self.entry_senha.insert(0, "Senha")
        self.entry_senha.bind("<FocusIn>", lambda e: on_entry_focus_in(e, self.entry_senha, "Senha"))
        self.entry_senha.bind("<FocusOut>", lambda e: on_entry_focus_out(e, self.entry_senha, "Senha"))
        self.entry_senha.pack(pady=5)

        tk.Button(self, text="Cadastrar", bg="#4CAF50", fg="white", command=self.cadastrar).pack(pady=10)
        tk.Button(self, text="Voltar", command=lambda: controller.show_frame("LoginPage")).pack()

    def cadastrar(self):
        usuario = self.entry_usuario.get()
        cpf = self.entry_cpf.get()
        senha = self.entry_senha.get()
        if usuario == "Usuário" or cpf == "CPF" or senha == "Senha":
            messagebox.showerror("Erro", "Preencha todos os campos")
            return
        if cadastrar_usuario(usuario, cpf, senha):
            messagebox.showinfo("Sucesso", "Usuário cadastrado com sucesso")
            self.controller.show_frame("LoginPage")
        else:
            messagebox.showerror("Erro", "Usuário já existe")

class NovoAdminPage(BasePage):
    def __init__(self, root, controller):
        super().__init__(root, controller)

        tk.Label(self, text="Criar Conta Administrador", font=("Arial", 16), bg="#e6f2ff").pack(pady=10)

        self.entry_chave = tk.Entry(self, fg="grey")
        self.entry_chave.insert(0, "Palavra-chave secreta")
        self.entry_chave.bind("<FocusIn>", lambda e: on_entry_focus_in(e, self.entry_chave, "Palavra-chave secreta"))
        self.entry_chave.bind("<FocusOut>", lambda e: on_entry_focus_out(e, self.entry_chave, "Palavra-chave secreta"))
        self.entry_chave.pack(pady=5)

        self.entry_usuario = tk.Entry(self, fg="grey")
        self.entry_usuario.insert(0, "Usuário Admin")
        self.entry_usuario.bind("<FocusIn>", lambda e: on_entry_focus_in(e, self.entry_usuario, "Usuário Admin"))
        self.entry_usuario.bind("<FocusOut>", lambda e: on_entry_focus_out(e, self.entry_usuario, "Usuário Admin"))
        self.entry_usuario.pack(pady=5)

        self.entry_senha = tk.Entry(self, fg="grey", show="")
        self.entry_senha.insert(0, "Senha Admin")
        self.entry_senha.bind("<FocusIn>", lambda e: on_entry_focus_in(e, self.entry_senha, "Senha Admin"))
        self.entry_senha.bind("<FocusOut>", lambda e: on_entry_focus_out(e, self.entry_senha, "Senha Admin"))
        self.entry_senha.pack(pady=5)

        btn_criar = tk.Button(self, text="Criar Conta", bg="#4CAF50", fg="white", command=self.criar_conta)
        btn_criar.pack(pady=10)

        tk.Button(self, text="Voltar", command=lambda: controller.show_frame("LoginPage")).pack()

        bind_enter_to_button(self.entry_chave, btn_criar)
        bind_enter_to_button(self.entry_usuario, btn_criar)
        bind_enter_to_button(self.entry_senha, btn_criar)

    def criar_conta(self):
        chave = self.entry_chave.get()
        usuario = self.entry_usuario.get()
        senha = self.entry_senha.get()
        if chave == "Palavra-chave secreta" or usuario == "Usuário Admin" or senha == "Senha Admin":
            messagebox.showerror("Erro", "Preencha todos os campos")
            return
        if chave != PALAVRA_CHAVE_ADMIN:
            messagebox.showerror("Erro", "Palavra-chave secreta incorreta")
            return
        if cadastrar_admin(usuario, senha):
            messagebox.showinfo("Sucesso", "Conta de administrador criada com sucesso")
            self.controller.show_frame("LoginPage")
        else:
            messagebox.showerror("Erro", "Conta de administrador já existe")

class MenuPage(BasePage):
    def __init__(self, root, controller):
        super().__init__(root, controller)
        tk.Label(self, text="Menu Principal", font=("Arial", 16), bg="#e6f2ff").pack(pady=10)
        tk.Button(self, text="Cadastrar Cliente", command=lambda: controller.show_frame("CadastroClientePage"), width=30).pack(pady=5)
        tk.Button(self, text="Listar Clientes", command=lambda: controller.show_frame("ListaClientesPage"), width=30).pack(pady=5)
        tk.Button(self, text="Buscar por CPF", command=lambda: controller.show_frame("BuscarCpfPage"), width=30).pack(pady=5)
        tk.Button(self, text="Sair", command=self.sair, width=30).pack(pady=5)

    def sair(self):
        self.controller.usuario_logado = None
        self.controller.admin_logado = False
        self.controller.show_frame("LoginPage")

class CadastroClientePage(BasePage):
    def __init__(self, root, controller):
        super().__init__(root, controller)
        tk.Label(self, text="Cadastro de Cliente", font=("Arial", 16), bg="#e6f2ff").pack(pady=10)

        self.e1 = tk.Entry(self, fg="grey")
        self.e1.insert(0, "Nome")
        self.e1.bind("<FocusIn>", lambda e: on_entry_focus_in(e, self.e1, "Nome"))
        self.e1.bind("<FocusOut>", lambda e: on_entry_focus_out(e, self.e1, "Nome"))
        self.e1.pack(pady=5)

        self.e2 = tk.Entry(self, fg="grey")
        self.e2.insert(0, "CPF")
        self.e2.bind("<FocusIn>", lambda e: on_entry_focus_in(e, self.e2, "CPF"))
        self.e2.bind("<FocusOut>", lambda e: on_entry_focus_out(e, self.e2, "CPF"))
        self.e2.bind('<KeyRelease>', lambda e: formatar_cpf(e, self.e2))
        self.e2.pack(pady=5)

        self.e3 = tk.Entry(self, fg="grey")
        self.e3.insert(0, "Telefone")
        self.e3.bind("<FocusIn>", lambda e: on_entry_focus_in(e, self.e3, "Telefone"))
        self.e3.bind("<FocusOut>", lambda e: on_entry_focus_out(e, self.e3, "Telefone"))
        self.e3.pack(pady=5)

        self.e4 = tk.Entry(self, fg="grey")
        self.e4.insert(0, "Email")
        self.e4.bind("<FocusIn>", lambda e: on_entry_focus_in(e, self.e4, "Email"))
        self.e4.bind("<FocusOut>", lambda e: on_entry_focus_out(e, self.e4, "Email"))
        self.e4.pack(pady=5)

        tk.Button(self, text="Cadastrar", bg="#4CAF50", fg="white", command=self.cadastrar).pack(pady=10)
        tk.Button(self, text="Voltar", command=lambda: controller.show_frame("MenuPage")).pack()

    def cadastrar(self):
        nome = self.e1.get()
        cpf = self.e2.get()
        telefone = self.e3.get()
        email = self.e4.get()

        # Verificar se campos foram preenchidos e não estão com placeholders
        if nome == "Nome" or cpf == "CPF" or telefone == "Telefone" or email == "Email":
            messagebox.showerror("Erro", "Preencha todos os campos")
            return
        cadastrar_cliente(nome, cpf, telefone, email)
        messagebox.showinfo("Sucesso", "Cliente cadastrado")
        self.controller.show_frame("MenuPage")

class ListaClientesPage(BasePage):
    def __init__(self, root, controller):
        super().__init__(root, controller)
        tk.Label(self, text="Lista de Clientes", font=("Arial", 16), bg="#e6f2ff").pack(pady=10)
        self.lista = tk.Listbox(self)
        self.lista.pack(pady=5, fill="both", expand=True)

        btn_detalhes = tk.Button(self, text="Ver detalhes", command=self.ver_detalhes)
        btn_detalhes.pack(pady=2)

        btn_excluir = tk.Button(self, text="Excluir Cliente", command=self.excluir_cliente)
        btn_excluir.pack(pady=2)

        tk.Button(self, text="Voltar", command=lambda: controller.show_frame("MenuPage")).pack(pady=5)

    def update_list(self):
        self.lista.delete(0, tk.END)
        for c in clientes:
            self.lista.insert(tk.END, c["nome"])

    def ver_detalhes(self):
        index = self.lista.curselection()
        if index:
            c = clientes[index[0]]
            dados = f"Nome: {c['nome']}\nCPF: {c['cpf']}\nTelefone: {c['telefone']}\nEmail: {c['email']}"
            messagebox.showinfo("Detalhes do Cliente", dados)
        else:
            messagebox.showwarning("Aviso", "Selecione um cliente para ver detalhes")

    def excluir_cliente(self):
        if not self.controller.admin_logado:
            messagebox.showerror("Erro", "Somente administradores podem excluir clientes")
            return
        index = self.lista.curselection()
        if not index:
            messagebox.showwarning("Aviso", "Selecione um cliente para excluir")
            return

        # Perguntar senha admin para confirmar
        senha = simpledialog.askstring("Confirmação", "Digite a senha do administrador para excluir:", show="*")
        if senha is None:
            return  # Cancelou

        admin_usuario = self.controller.usuario_logado
        admin_info = usuarios.get(admin_usuario)

        if not admin_info or admin_info.get("senha") != senha:
            messagebox.showerror("Erro", "Senha incorreta")
            return

        remover_cliente(index[0])
        messagebox.showinfo("Sucesso", "Cliente excluído com sucesso")
        self.update_list()

class BuscarCpfPage(BasePage):
    def __init__(self, root, controller):
        super().__init__(root, controller)
        tk.Label(self, text="Buscar Cliente por CPF", font=("Arial", 16), bg="#e6f2ff").pack(pady=10)

        self.entry_cpf = tk.Entry(self, fg="grey")
        self.entry_cpf.insert(0, "Digite o CPF")
        self.entry_cpf.bind("<FocusIn>", lambda e: on_entry_focus_in(e, self.entry_cpf, "Digite o CPF"))
        self.entry_cpf.bind("<FocusOut>", lambda e: on_entry_focus_out(e, self.entry_cpf, "Digite o CPF"))
        self.entry_cpf.bind('<KeyRelease>', lambda e: formatar_cpf(e, self.entry_cpf))
        self.entry_cpf.pack(pady=5)

        btn_buscar = tk.Button(self, text="Buscar", bg="#4CAF50", fg="white", command=self.buscar)
        btn_buscar.pack(pady=5)

        tk.Button(self, text="Voltar", command=lambda: controller.show_frame("MenuPage")).pack()

        bind_enter_to_button(self.entry_cpf, btn_buscar)

    def buscar(self):
        cpf = self.entry_cpf.get()
        if cpf == "Digite o CPF":
            messagebox.showerror("Erro", "Digite um CPF válido")
            return
        cliente = buscar_cliente_por_cpf(cpf)
        if cliente:
            dados = f"Nome: {cliente['nome']}\nTelefone: {cliente['telefone']}\nEmail: {cliente['email']}"
            messagebox.showinfo("Cliente encontrado", dados)
        else:
            messagebox.showerror("Erro", "Cliente não encontrado")

if __name__ == '__main__':
    root = tk.Tk()
    app = App(root)
    root.mainloop()
