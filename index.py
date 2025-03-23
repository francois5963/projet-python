import tkinter as tk
from tkinter import messagebox
import paramiko

# ------------------------------------------------------------------------
# La classe "ServerManagerApp" hérite de "tk.Tk", ce qui signifie que
# l'application elle-même est une fenêtre Tkinter.
# ------------------------------------------------------------------------
class ServerManagerApp(tk.Tk):
    def __init__(self):
        # On appelle le constructeur de la classe parente (tk.Tk).
        super().__init__()
        
        # On définit le titre de la fenêtre.
        self.title("Connexion au serveur")

        # Ces variables stockeront l'IP, le nom d'utilisateur et le mot de passe
        # lorsque la connexion sera validée.
        self.server_ip = None
        self.server_username = None
        self.server_password = None

        # On lance directement la fonction qui affiche l'écran de connexion.
        self.show_login_screen()

    # ---------------------------------------------------------------------
    # Fonction pour afficher l'écran de connexion (login).
    # ---------------------------------------------------------------------
    def show_login_screen(self):
        """
        Affiche les champs pour saisir l'IP, le nom d'utilisateur, le mot de passe,
        et un bouton pour valider la connexion.
        """
        # Pour être sûr de repartir d'un espace vide, on détruit tous les widgets
        # éventuellement déjà présents dans la fenêtre.
        for widget in self.winfo_children():
            widget.destroy()

        # Label pour l'IP
        tk.Label(self, text="Adresse IP du serveur :").grid(row=0, column=0, padx=10, pady=10)
        # Champ de saisie pour l'IP
        self.ip_entry = tk.Entry(self)
        self.ip_entry.grid(row=0, column=1, padx=10, pady=10)

        # Label pour le nom d'utilisateur
        tk.Label(self, text="Nom d'utilisateur :").grid(row=1, column=0, padx=10, pady=10)
        # Champ de saisie pour le nom d'utilisateur
        self.user_entry = tk.Entry(self)
        self.user_entry.grid(row=1, column=1, padx=10, pady=10)

        # Label pour le mot de passe
        tk.Label(self, text="Mot de passe :").grid(row=2, column=0, padx=10, pady=10)
        # Champ de saisie pour le mot de passe (avec show="*" pour masquer)
        self.pass_entry = tk.Entry(self, show="*")
        self.pass_entry.grid(row=2, column=1, padx=10, pady=10)

        # Bouton "Se connecter" qui appelle la méthode "se_connecter"
        connect_button = tk.Button(
            self,
            text="Se connecter",
            command=self.se_connecter
        )
        connect_button.grid(row=3, column=0, columnspan=2, pady=20)

    # ---------------------------------------------------------------------
    # Fonction appelée lorsqu'on clique sur "Se connecter".
    # ---------------------------------------------------------------------
    def se_connecter(self):
        """
        Récupère les infos saisies, vérifie la connexion SSH et
        ouvre le menu principal si tout va bien.
        """
        # On lit le contenu des champs de saisie
        ip = self.ip_entry.get().strip()
        username = self.user_entry.get().strip()
        password = self.pass_entry.get()

        # On appelle la fonction "verifier_identifiants" pour tester la connexion
        if self.verifier_identifiants(ip, username, password):
            # Si ça marche, on sauvegarde ces informations dans l'application
            self.server_ip = ip
            self.server_username = username
            self.server_password = password

            # Puis on affiche le menu principal
            self.show_menu_screen()
        else:
            # Sinon, on affiche un message d'erreur
            messagebox.showerror("Erreur de connexion", "Identifiants invalides ou serveur injoignable.")

    # ---------------------------------------------------------------------
    # Vérifie la validité des identifiants SSH en tentant une connexion.
    # ---------------------------------------------------------------------
    def verifier_identifiants(self, ip, username, password):
        """Retourne True si la connexion SSH fonctionne, False sinon."""
        ssh = paramiko.SSHClient()
        # On accepte automatiquement la clé d'hôte si elle n'est pas connue.
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            # Tentative de connexion SSH avec un timeout de 5 secondes
            ssh.connect(ip, username=username, password=password, timeout=5)
            ssh.close()
            return True
        except paramiko.AuthenticationException:
            # Erreur d'authentification => retourne False
            return False
        except Exception:
            # Toute autre erreur => False
            return False

    # ---------------------------------------------------------------------
    # Affiche le menu principal (Ajouter, Modifier, Supprimer, Liste, etc.).
    # ---------------------------------------------------------------------
    def show_menu_screen(self):
        """
        Efface l'écran de connexion et met en place les boutons du menu.
        """
        # On enlève tout ce qui est déjà dans la fenêtre
        for widget in self.winfo_children():
            widget.destroy()

        # On change le titre de la fenêtre
        self.title("Menu principal")

        # Label principal
        label_menu = tk.Label(self, text="Menu principal", font=("Arial", 16, "bold"))
        label_menu.pack(pady=20)

        # Bouton pour "Ajouter" un utilisateur
        btn_ajouter = tk.Button(
            self,
            text="Ajouter",
            command=self.action_ajouter
        )
        # Bouton pour "Modifier" un utilisateur
        btn_modifier = tk.Button(
            self,
            text="Modifier",
            command=self.action_modifier
        )
        # Bouton pour "Supprimer" un utilisateur
        btn_supprimer = tk.Button(
            self,
            text="Supprimer",
            command=self.action_supprimer
        )
        # Bouton pour "Liste" des utilisateurs
        btn_liste = tk.Button(
            self,
            text="Liste",
            command=self.action_liste
        )
        # Bouton "Déconnexion"
        btn_deconnexion = tk.Button(
            self,
            text="Déconnexion",
            command=self.deconnecter
        )

        # On les place dans la fenêtre
        btn_ajouter.pack(pady=5)
        btn_modifier.pack(pady=5)
        btn_supprimer.pack(pady=5)
        btn_liste.pack(pady=5)
        btn_deconnexion.pack(pady=5)

    # ---------------------------------------------------------------------
    # Déconnexion : on efface les infos et on revient à l'écran de login.
    # ---------------------------------------------------------------------
    def deconnecter(self):
        """
        Réinitialise les variables de connexion et relance l'écran de login.
        """
        self.server_ip = None
        self.server_username = None
        self.server_password = None

        self.show_login_screen()

    # ---------------------------------------------------------------------
    # ACTION : Ajouter un utilisateur
    # ---------------------------------------------------------------------
    def action_ajouter(self):
        """Ouvre une fenêtre pour saisir les infos du nouvel utilisateur (nom + mdp)."""
        # On crée une nouvelle fenêtre "Toplevel" (sous-fenêtre)
        add_window = tk.Toplevel(self)
        add_window.title("Ajouter un nouvel utilisateur")

        # Label et champ pour le nom du nouvel utilisateur
        lbl_new_user = tk.Label(add_window, text="Nom du nouvel utilisateur :")
        lbl_new_user.grid(row=0, column=0, padx=10, pady=10)
        entry_new_user = tk.Entry(add_window)
        entry_new_user.grid(row=0, column=1, padx=10, pady=10)

        # Label et champ pour le mot de passe
        lbl_new_pass = tk.Label(add_window, text="Mot de passe :")
        lbl_new_pass.grid(row=1, column=0, padx=10, pady=10)
        entry_new_pass = tk.Entry(add_window, show="*")
        entry_new_pass.grid(row=1, column=1, padx=10, pady=10)

        # Label et champ pour confirmer le mot de passe
        lbl_confirm_pass = tk.Label(add_window, text="Confirmer le mot de passe :")
        lbl_confirm_pass.grid(row=2, column=0, padx=10, pady=10)
        entry_confirm_pass = tk.Entry(add_window, show="*")
        entry_confirm_pass.grid(row=2, column=1, padx=10, pady=10)

        def creer_utilisateur():
            """
            Vérifie que les champs sont remplis et que les mots de passe
            correspondent, puis exécute la commande SSH pour créer l'utilisateur.
            """
            new_user = entry_new_user.get().strip()
            new_pass = entry_new_pass.get()
            confirm_pass = entry_confirm_pass.get()

            # Vérifications de base
            if not new_user or not new_pass or not confirm_pass:
                messagebox.showwarning("Attention", "Veuillez renseigner tous les champs.")
                return

            if new_pass != confirm_pass:
                messagebox.showwarning("Attention", "Les deux mots de passe ne correspondent pas.")
                return

            try:
                # Connexion SSH avec Paramiko
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(self.server_ip, username=self.server_username, password=self.server_password, timeout=5)

                # Commande Linux pour créer l'utilisateur et définir son mot de passe
                command = (
                    f"echo '{self.server_password}' | sudo -S useradd -m {new_user} && "
                    f"echo '{self.server_password}' | sudo -S sh -c \"echo '{new_user}:{new_pass}' | chpasswd\""
                )

                stdin, stdout, stderr = ssh.exec_command(command)
                exit_status = stdout.channel.recv_exit_status()

                if exit_status == 0:
                    messagebox.showinfo("Succès", f"L'utilisateur '{new_user}' a été créé avec succès.")
                else:
                    errors = stderr.read().decode("utf-8")
                    messagebox.showerror("Erreur", f"Échec de la création de l'utilisateur.\n{errors}")

                ssh.close()

            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible de créer l'utilisateur :\n{e}")

        # Bouton pour valider la création
        btn_creer = tk.Button(add_window, text="Créer l'utilisateur", command=creer_utilisateur)
        btn_creer.grid(row=3, column=0, columnspan=2, pady=10)

    # ---------------------------------------------------------------------
    # ACTION : Modifier un utilisateur
    # ---------------------------------------------------------------------
    def action_modifier(self):
        """Ouvre une fenêtre pour changer le nom d'un utilisateur et/ou son mot de passe."""
        modify_window = tk.Toplevel(self)
        modify_window.title("Modifier un utilisateur")

        # Ancien nom d'utilisateur
        lbl_old_user = tk.Label(modify_window, text="Ancien nom d'utilisateur :")
        lbl_old_user.grid(row=0, column=0, padx=10, pady=5)
        entry_old_user = tk.Entry(modify_window)
        entry_old_user.grid(row=0, column=1, padx=10, pady=5)

        # Nouveau nom d'utilisateur (facultatif)
        lbl_new_user = tk.Label(modify_window, text="Nouveau nom d'utilisateur :")
        lbl_new_user.grid(row=1, column=0, padx=10, pady=5)
        entry_new_user = tk.Entry(modify_window)
        entry_new_user.grid(row=1, column=1, padx=10, pady=5)

        # Nouveau mot de passe (facultatif)
        lbl_new_pass = tk.Label(modify_window, text="Nouveau mot de passe :")
        lbl_new_pass.grid(row=2, column=0, padx=10, pady=5)
        entry_pass = tk.Entry(modify_window, show="*")
        entry_pass.grid(row=2, column=1, padx=10, pady=5)

        # Confirmation du nouveau mot de passe
        lbl_confirm_pass = tk.Label(modify_window, text="Confirmer le mot de passe :")
        lbl_confirm_pass.grid(row=3, column=0, padx=10, pady=5)
        entry_confirm_pass = tk.Entry(modify_window, show="*")
        entry_confirm_pass.grid(row=3, column=1, padx=10, pady=5)

        def modifier_utilisateur():
            """
            Récupère l'ancien nom, le nouveau nom, le nouveau mot de passe (optionnel),
            puis exécute usermod / chpasswd selon les besoins.
            """
            old_user = entry_old_user.get().strip()
            new_user = entry_new_user.get().strip()
            new_pass = entry_pass.get()
            confirm_pass = entry_confirm_pass.get()

            # Si on n'a pas d'ancien nom, on ne sait pas qui modifier
            if not old_user:
                messagebox.showwarning("Attention", "Veuillez renseigner l'ancien nom d'utilisateur.")
                return

            # Va-t-on renommer l'utilisateur ?
            rename_wanted = (new_user != "" and new_user != old_user)
            # Va-t-on changer le mot de passe ?
            pass_wanted = (new_pass != "" or confirm_pass != "")

            # Si on remplit l'un des champs pour le mot de passe, il faut les deux
            if pass_wanted:
                if not new_pass or not confirm_pass:
                    messagebox.showwarning("Attention", "Veuillez renseigner le mot de passe ET la confirmation.")
                    return
                if new_pass != confirm_pass:
                    messagebox.showwarning("Attention", "Les deux mots de passe ne correspondent pas.")
                    return

            # Si on ne veut ni renommer ni changer le mot de passe
            if not rename_wanted and not pass_wanted:
                messagebox.showinfo("Information", "Aucune modification demandée.")
                return

            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(self.server_ip, username=self.server_username, password=self.server_password, timeout=5)

                # Si on veut renommer
                if rename_wanted:
                    rename_cmd = (
                        f"echo '{self.server_password}' | sudo -S usermod -l {new_user} {old_user} && "
                        f"echo '{self.server_password}' | sudo -S usermod -d /home/{new_user} -m {new_user}"
                    )
                    stdin, stdout, stderr = ssh.exec_command(rename_cmd)
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status != 0:
                        errors = stderr.read().decode("utf-8")
                        messagebox.showerror("Erreur", f"Échec du renommage.\n{errors}")
                        ssh.close()
                        return
                    # Maintenant, le compte s'appelle new_user
                    effective_user = new_user
                else:
                    effective_user = old_user

                # Si on veut changer le mot de passe
                if pass_wanted:
                    pass_cmd = (
                        f"echo '{self.server_password}' | sudo -S sh -c \"echo '{effective_user}:{new_pass}' | chpasswd\""
                    )
                    stdin, stdout, stderr = ssh.exec_command(pass_cmd)
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status != 0:
                        errors = stderr.read().decode("utf-8")
                        messagebox.showerror("Erreur", f"Échec de la modification du mot de passe.\n{errors}")
                        ssh.close()
                        return

                ssh.close()

                # On affiche un message final en fonction de ce qui a été fait
                if rename_wanted and pass_wanted:
                    messagebox.showinfo("Succès", f"L'utilisateur '{old_user}' a été renommé en '{new_user}', et mot de passe modifié.")
                elif rename_wanted:
                    messagebox.showinfo("Succès", f"L'utilisateur '{old_user}' a été renommé en '{new_user}'.")
                elif pass_wanted:
                    messagebox.showinfo("Succès", f"Le mot de passe de '{old_user}' a été modifié.")

            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible de modifier l'utilisateur :\n{e}")

        # Bouton pour valider la modification
        btn_modifier_user = tk.Button(modify_window, text="Modifier l'utilisateur", command=modifier_utilisateur)
        btn_modifier_user.grid(row=4, column=0, columnspan=2, pady=10)

    # ---------------------------------------------------------------------
    # ACTION : Supprimer un utilisateur
    # ---------------------------------------------------------------------
    def action_supprimer(self):
        """Ouvre une fenêtre pour saisir le nom d'utilisateur à supprimer."""
        remove_window = tk.Toplevel(self)
        remove_window.title("Supprimer un utilisateur")

        lbl_user = tk.Label(remove_window, text="Nom de l'utilisateur à supprimer :")
        lbl_user.grid(row=0, column=0, padx=10, pady=10)
        entry_user = tk.Entry(remove_window)
        entry_user.grid(row=0, column=1, padx=10, pady=10)

        def supprimer_utilisateur():
            """
            Demande confirmation, puis exécute userdel -r <user_to_remove>
            pour supprimer le compte et son dossier home.
            """
            user_to_remove = entry_user.get().strip()
            if not user_to_remove:
                messagebox.showwarning("Attention", "Veuillez renseigner le nom d'utilisateur à supprimer.")
                return

            confirm = messagebox.askyesno(
                "Confirmation",
                f"Voulez-vous vraiment supprimer l'utilisateur '{user_to_remove}' et son répertoire home ?"
            )
            if not confirm:
                return

            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(self.server_ip, username=self.server_username, password=self.server_password, timeout=5)

                command = f"echo '{self.server_password}' | sudo -S userdel -r {user_to_remove}"
                stdin, stdout, stderr = ssh.exec_command(command)
                exit_status = stdout.channel.recv_exit_status()

                if exit_status == 0:
                    messagebox.showinfo("Succès", f"L'utilisateur '{user_to_remove}' a été supprimé avec succès.")
                else:
                    errors = stderr.read().decode("utf-8")
                    messagebox.showerror("Erreur", f"Échec de la suppression.\n{errors}")

                ssh.close()

            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible de supprimer l'utilisateur :\n{e}")

        btn_supprimer_user = tk.Button(remove_window, text="Supprimer l'utilisateur", command=supprimer_utilisateur)
        btn_supprimer_user.grid(row=1, column=0, columnspan=2, pady=10)

    # ---------------------------------------------------------------------
    # ACTION : Lister les utilisateurs (UID >= 1000) et afficher leur HACHÉ
    # ---------------------------------------------------------------------
    def action_liste(self):
        """
        Ouvre une fenêtre et affiche la liste des utilisateurs en se basant
        sur 'getent passwd' (pour le nom et l'UID) et 'sudo cat /etc/shadow' 
        pour récupérer le mot de passe haché. 
        Seuls les utilisateurs avec UID >= 1000 sont affichés.
        
        Remarque : Il est impossible d'obtenir le mot de passe en clair,
        on ne voit que le haché (SHA512, MD5, etc.).
        """
        list_window = tk.Toplevel(self)
        list_window.title("Liste des utilisateurs")

        # On agrandit un peu la zone de texte pour pouvoir afficher username | hash
        text_area = tk.Text(list_window, width=80, height=20)
        text_area.pack(padx=10, pady=10)

        try:
            # 1) Connexion SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.server_ip, username=self.server_username, password=self.server_password, timeout=5)

            # 2) Récupérer la liste des utilisateurs depuis /etc/passwd
            command_passwd = "getent passwd"
            stdin, stdout, stderr = ssh.exec_command(command_passwd)
            output_passwd = stdout.read().decode("utf-8").strip()

            # 3) Récupérer /etc/shadow via sudo pour lire le haché des mots de passe
            command_shadow = f"echo '{self.server_password}' | sudo -S cat /etc/shadow"
            stdin, stdout, stderr = ssh.exec_command(command_shadow)
            output_shadow = stdout.read().decode("utf-8").strip()

            # 4) Fermeture de la connexion SSH
            ssh.close()

            # 5) Construire un dictionnaire user -> hash à partir du contenu de /etc/shadow
            shadow_dict = {}
            shadow_lines = output_shadow.splitlines()
            for line in shadow_lines:
                fields = line.split(":")
                if len(fields) < 2:
                    continue
                user_shadow = fields[0]
                hash_shadow = fields[1]  # Contient le mot de passe haché (ou '!'/'*' etc.)
                shadow_dict[user_shadow] = hash_shadow

            # 6) Parcourir la liste des utilisateurs de /etc/passwd
            #    et filtrer ceux qui ont un UID >= 1000.
            passwd_lines = output_passwd.splitlines()
            for line in passwd_lines:
                fields = line.split(":")
                if len(fields) < 3:
                    continue
                username = fields[0]
                uid_str = fields[2]

                # On vérifie si c'est un nombre et si UID >= 1000
                if uid_str.isdigit():
                    uid = int(uid_str)
                    if uid >= 1000:
                        # On cherche le hash dans le dictionnaire shadow_dict
                        hashed_pass = shadow_dict.get(username, "N/A")
                        # On insère dans la zone de texte : "username | haché"
                        text_area.insert(tk.END, f"{username} | {hashed_pass}\n")

        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de récupérer la liste des utilisateurs :\n{e}")

# -----------------------------------------------------------------------------
# Point d'entrée du programme
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # On crée une instance de "ServerManagerApp" et on lance la boucle Tkinter
    app = ServerManagerApp()
    app.mainloop()
