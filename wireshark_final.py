import threading
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf, send, wrpcap, rdpcap, hexdump
import re

# Couleurs personnalisées pour le thème sombre de l’interface
BACKGROUND = "#373737"
LIGHT_BACKGROUND = "#5D5D5D"
SLIGHT_BACKGROUND = "#969696"
BORDER = "#757575"
LIGHT_BORDER = "#C7C7C7"
DARK_BLUE = "#738FFF"
DARK_YELLOW = "#FFFD7D"
DARK_GREEN = "#82FF7B"

font_mono = ("Courier", 12) # Police monospace pour alignement des champs

def tabify(string, strlen, tab=26):
    """Centre une chaîne dans un espace de longueur fixe (utile pour aligner visuellement les adresses dans la liste)"""
    string = " "*((tab-strlen)//2 if (tab-strlen)%2 == 0 else ((tab-strlen)//2)+1) + string + " "*((tab-strlen)//2)
    return string

class PacketSniffer:
    """Classe responsable de la capture de paquets avec Scapy"""
    def __init__(self, packet_callback, filter_rule=""):
        self.sniff_thread = None              # Thread de capture
        self.running = False                  # Indique si la capture est active
        self.packet_callback = packet_callback  # Fonction à appeler pour chaque paquet capturé
        self.filter_rule = filter_rule        # Filtre de capture BPF (ex: 'tcp or udp')

    def start(self):
        """Démarre la capture dans un thread séparé"""
        self.running = True
        self.sniff_thread = threading.Thread(target=self._sniff_packets)
        self.sniff_thread.daemon = True     # Permet d’arrêter le thread avec le programme
        self.sniff_thread.start()

    def stop(self):
        """Demande l’arrêt de la capture en changeant l'état et en forçant sniff() à se débloquer"""
        self.running = False
        self._wake_sniffer()

    def _wake_sniffer(self):
        """Injecte un paquet loopback pour forcer sniff() à sortir du blocage"""
        try:
            ip = conf.iface.ip # Récupère l'IP locale pour envoyer un paquet
            send(IP(dst=ip)/ICMP(), verbose=0)  # Envoie un ping vers soi-même
        except Exception as e:
            print(f"[Wake Sniffer] Erreur : {e}")

    def _sniff_packets(self):
        """Capture les paquets en boucle tant que running est True"""
        try:
            sniff(
                prn=self._process_packet,   # Fonction appelée à chaque paquet capturé
                filter=self.filter_rule,    # Filtrage au niveau de la capture (BPF)
                store=False,    # Ne stocke pas les paquets dans une liste interne
                stop_filter=lambda x: not self.running  # Stoppe la capture si l'état running devient False
            )
        except Exception as e:
            print(f"[ERREUR] Filtrage BPF invalide ou libpcap manquant : {e}")

    def _process_packet(self, packet):
        """Traitement de chaque paquet capturé"""
        if IP in packet:
            # Extraction du protocole (TCP, UDP, etc.) depuis les données du paquet
            proto = re.search(r"proto\s*=\s*([^\s]+)", packet.show(dump=True)).group(1).upper()

            # Création d’un dictionnaire avec les infos essentielles du paquet
            info = {
                'time': datetime.fromtimestamp(packet.time),
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'proto': proto,
                'sport': packet.sport if TCP in packet or UDP in packet else '',
                'dport': packet.dport if TCP in packet or UDP in packet else '',
                'details': packet.summary() + "\n\n" + str(packet.show(dump=True))
            }

            # Envoi des données à l’interface graphique
            self.packet_callback(info, packet)


class PacketSnifferGUI:
    """Interface graphique Tkinter pour afficher les paquets"""
    def __init__(self, root):
        self.root = root    # Fenêtre principale
        self.root.title("Wireshark Lite - Python Edition by Simon & Luc")
        self.packets = []   # Liste contenant tous les paquets capturés
        self.saved_packets = []
        self.pause = False

        self.filter_var = tk.StringVar()    # Variable de filtre BPF (tcp, udp, etc.)
        self.pcap_var = tk.StringVar()  # Variable de nom du fichier pcap
        
        self._build_gui()   # Création des éléments de l’interface 
        self.apply_dark_theme() # Application du thème sombre

        self.sniffer = PacketSniffer(self._add_packet)  # Initialise le sniffer avec la fonction de rappel

    def apply_dark_theme(self):
        """Applique un thème sombre uniforme à l'interface"""

        # Fond général de la fenêtre principale
        self.root.configure(
            bg=BACKGROUND,              # fond et texte
            highlightbackground=BORDER,          # bordure inactive
            highlightcolor=LIGHT_BORDER,                 # bordure active
        )

        # Configuration manuelle pour les widgets Tk "classiques"
        self.details_text.configure(
            bg=BACKGROUND, fg="white",              # fond et texte
            insertbackground="white",              # curseur insertion
            selectbackground=LIGHT_BACKGROUND,               # fond sélection
            selectforeground="white",              # texte sélection
            highlightbackground=BORDER,          # bordure inactive
            highlightcolor=LIGHT_BORDER,                 # bordure active
            highlightthickness=1, bd=1, relief="flat"
        )

        self.details_hextext.configure(
            bg=BACKGROUND, fg="white",              # fond et texte
            insertbackground="white",              # curseur insertion
            selectbackground=LIGHT_BACKGROUND,               # fond sélection
            selectforeground="white",              # texte sélection
            highlightbackground=BORDER,          # bordure inactive
            highlightcolor=LIGHT_BORDER,                 # bordure active
            highlightthickness=1, bd=1, relief="flat"
        )

        self.packet_list.configure(
            bg=BACKGROUND, fg="black",         # fond et texte
            selectbackground=LIGHT_BORDER, selectforeground="black",
            highlightbackground=BORDER,          # bordure inactive
            highlightcolor=LIGHT_BORDER,                 # bordure active
            highlightthickness=1, bd=1, relief="flat",
            font=font_mono
        )

        # Initialisation et choix du thème ttk
        style = ttk.Style()
        style.theme_use("clam")  # Permet de personnaliser les bordures et fonds

        # Configuration des styles de base pour tous les widgets ttk
        style.configure(
            "TFrame",
            background=BACKGROUND
        )  # fond des frames

        style.configure(
            "TLabel",
            background=BACKGROUND, 
            foreground="white"
        )  # textes

        style.configure(
            "TButton",
            background=LIGHT_BACKGROUND, foreground="white",
            borderwidth=1, relief="flat"
        )  # boutons plats

        style.map("TButton", background=[("active", SLIGHT_BACKGROUND)])  # survol

        style.configure(
            "TEntry",
            fieldbackground=LIGHT_BACKGROUND, foreground="white",
            background=SLIGHT_BACKGROUND,
            borderwidth=1, relief="flat"
        )  # champ texte

        style.map("TEntry", background=[("active", SLIGHT_BACKGROUND)])  # contour focus

        style.configure("TScrollbar",
                        background=BACKGROUND, troughcolor="#222222",
                        arrowcolor="white", borderwidth=1, relief="flat")

        # LED d'état (label statique non stylé automatiquement)
        self.status_led.configure(background=BACKGROUND, foreground="red")


    def _build_gui(self):
        """Construit les éléments graphiques (barre de filtre, liste, détails)"""

        # Création des frames root
        frm = ttk.Frame(self.root, style="TFrame")
        frm.pack(fill="both", expand=True)

        ctrl_frame = ttk.Frame(frm, style="TFrame")
        ctrl_frame.pack(fill="both")

        # Affichage des barres d'entré dans une frame structuré en grille
        ent_frame = ttk.Frame(ctrl_frame, style="TFrame")
        ent_frame.pack(side="left", fill="both", padx=10, pady=5, expand=True)

        ttk.Label(ent_frame, text="Filtre (tcp, udp, host x.x.x.x) :", style="TLabel").grid(row=0, column=0, padx=5, pady=5)
        self.filter_entry = ttk.Entry(ent_frame, textvariable=self.filter_var, width=50, style="TEntry")
        self.filter_entry.grid(row=0, column=1, padx=5, pady=10)

        ttk.Label(ent_frame, text="PCAP file name (in same dir as .py) :", style="TLabel").grid(row=1, column=0, padx=5, pady=5)
        self.pcap_entry = ttk.Entry(ent_frame, textvariable=self.pcap_var, width=50, style="TEntry")
        self.pcap_entry.grid(row=1, column=1, padx=5, pady=10)

        # Affichage des boutons dans une frame structuré en grille
        btn_frame = ttk.Frame(ctrl_frame, style="TFrame")
        btn_frame.pack(side="left", fill="both", padx=10, pady=5, expand=True)

        ttk.Button(btn_frame, text="Démarrer", command=self.start_capture, style="TButton").grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(btn_frame, text="Arrêter", command=self.stop_capture, style="TButton").grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(btn_frame, text="Importer pcap", command=self.import_pcap, style="TButton").grid(row=1, column=0, padx=5, pady=5)
        ttk.Button(btn_frame, text="Exporter pcap", command=self.export_pcap, style="TButton").grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(btn_frame, text="Pause", command=self.pause_capture, style="TButton").grid(row=2, column=0, padx=5, pady=5)
        ttk.Button(btn_frame, text="Reprise", command=self.restart_capture, style="TButton").grid(row=2, column=1, padx=5, pady=5)

        # LED état
        self.status_led = ttk.Label(btn_frame, text="Arrêté", foreground="red")
        self.status_led.grid(row=0, column=2, padx=5, pady=5)

        # Affiche la liste des paquets capturé
        self.packet_list = tk.Listbox(frm, height=20)
        self.packet_list.pack(fill="both", expand=True)
        self.packet_list.bind("<<ListboxSelect>>", self.show_packet_details)

        # Affiche le détails du paquet séléctionné
        details_frame = ttk.Frame(frm, style="TFrame")
        details_frame.pack(fill="both", expand=True)

        self.details_text = scrolledtext.ScrolledText(details_frame, height=15)
        self.details_text.pack(side="left", fill="x", expand=True)

        self.details_hextext = scrolledtext.ScrolledText(details_frame, height=15)
        self.details_hextext.pack(side="left", fill="x", expand=True)

    def import_pcap(self):
        """Import de la capture en pcap"""
        imported_packets = rdpcap(self.pcap_entry.get())
        for pkt in imported_packets:
            self.sniffer._process_packet(pkt)

    def export_pcap(self):
        """Export de la capture en pcap"""
        filename = self.pcap_entry.get()
        if filename[-5:] != ".pcap" or filename[-4:] != ".cap": filename+=".pcap"
        wrpcap(filename, self.saved_packets)

    def start_capture(self):
        """Lance la capture avec le filtre spécifié"""
        self.pause = False
        self.stop_capture() # Arrête toute capture en cours
        self.packets.clear()     # Vide la liste de paquets
        self.saved_packets.clear()
        self.packet_list.delete(0, tk.END)  # Réinitialise l'affichage des paquets
        self.details_text.delete("1.0", tk.END) # Vide la zone de détails
        self.details_hextext.delete("1.0", tk.END) # Vide la zone de détails

        self.sniffer = PacketSniffer(self._add_packet)
        self.sniffer.filter_rule = self.filter_var.get()
        self.sniffer.start()
        self.status_led.config(text="En cours", foreground="green") # Affiche l’état actif

    
    def restart_capture(self):
        """Reprend la capture"""
        self.pause = False
        self.status_led.config(text="En cours", foreground="green") # Affiche l’état actif

    def stop_capture(self):
        """Stoppe proprement la capture et met à jour l’état dans l’interface"""
        if hasattr(self, "sniffer"):
            self.sniffer.stop()
            if self.sniffer.sniff_thread:
                self.sniffer.sniff_thread.join(timeout=1)
            self.status_led.config(text="Arrêté", foreground="red") # Affiche l’état inactif
    
    def pause_capture(self):
        """Met la la capture en pause"""
        self.pause = True
        self.status_led.config(text="En pause", foreground="yellow") # Affiche l’état actif

    def _add_packet(self, pkt_info, packet):
        """Formate et ajoute un paquet dans la liste avec une couleur par protocole"""

        self.packets.append(pkt_info)
        
        # Mise en forme du texte source/destination (centrage + port)
        displaytime = tabify(f"{pkt_info['time']}", len(str(pkt_info['time'])), 28)
        displaysrc = tabify(f"{pkt_info['src']}:{pkt_info['sport']}", 1+len(str(pkt_info['src']))+len(str(pkt_info['sport'])))
        displaydst = tabify(f"{pkt_info['dst']}:{pkt_info['dport']}", 1+len(str(pkt_info['dst']))+len(str(pkt_info['dport'])))
        displayproto = tabify(f"{pkt_info['proto']}",len(str(pkt_info['proto'])), 7)

        # Affichage structuré
        display = "|" + displaytime + "| src: "+displaysrc +"| dst:"+ displaydst + "|" + displayproto + "|"

        # Couleur différente selon le protocole
        color = DARK_BLUE if pkt_info['proto'] == "TCP" else DARK_YELLOW if pkt_info['proto'] == "UDP" else DARK_GREEN if pkt_info['proto'] == "ICMP" else LIGHT_BACKGROUND

        
        if not self.pause:
            self.packet_list.insert(tk.END, display) #tk.END
            self.saved_packets.append(packet) # Sauvegarde des paquets pour export pcap

        self.packet_list.itemconfig(tk.END, {'bg': color})

    def show_packet_details(self, event):
        """Affiche les détails du paquet sélectionné en évitant les erreurs d'index"""
        selection = self.packet_list.curselection()
        if selection:
            index = selection[0]
            if index < len(self.packets):  # Vérifie que l'index est valide
                details = self.packets[index]['details']
                hexdetails = hexdump(self.saved_packets[index], dump=True)
                self.details_text.delete("1.0", tk.END)
                self.details_hextext.delete("1.0", tk.END)
                self.details_text.insert(tk.END, details)
                self.details_hextext.insert(tk.END, hexdetails)
            else:
                # En cas de désynchronisation (paquet supprimé), on vide l’affichage
                self.details_text.delete("1.0", tk.END)
                self.details_hextext.delete("1.0", tk.END)



if __name__ == "__main__":
    root = tk.Tk()  # Crée la fenêtre principale
    app = PacketSnifferGUI(root)    # Initialise l'interface graphique
    root.mainloop() # Lance la boucle principale Tkinter (reste à l'écoute)
