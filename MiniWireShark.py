import tkinter as tk
from tkinter import filedialog, ttk
import threading
from collections import Counter
from datetime import datetime
import csv

from scapy.all import sniff, IP, TCP, UDP

################# Matplotlib #################

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

################### GLOBAL PART ###################

running =False
packet_count = 0

packet_logs = []
ip_counter = Counter()


graph_data = []
graph_x = []


################### PACKET PROCESSING ###################

def process_packet(packet):
    global packet_count

    protocol_filter = protocol_var.get()
    ip_filter = ip_entry.get().strip()

    protocol = "OTHER"

################### DETECT PROTOCOL ###################

    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"

################### HTTP DETECTION ###################

    if packet.haslayer(TCP):
        try:
            sport = packet[TCP].sport
            dport = packet[TCP].dport

            if sport == 80 or dport == 80:
                protocol = "HTTP"
        except:
            pass

################### PROTOCOL FILTERING ###################

    if protocol_filter != "ALL":
        if protocol != protocol_filter:
            return
        
################### IP FILTERING ###################

    src = "N/A"
    dst = "N/A"

    if IP in packet:
     src = packet[IP].src
     dst = packet[IP].dst

     if ip_filter:
         if ip_filter not in (src,dst):
             return
         
################### TOP TALKERS ###################

     ip_counter[src] += 1
    packet_count += 1

    count_label.config(text=f"Packets: {packet_count}")

    timestamp = datetime.now().strftime("%H:%M:%S")

    log = f"[{timestamp}] {src} -> {dst} | {protocol}"

################### SAVE LOGS ###################

    packet_logs.append([timestamp, src, dst, protocol])

################### COLORIZED OUTPUT ###################

    if protocol == "TCP":
        color = "tcp"

    elif protocol == "UDP":
        color = "udp"

    elif protocol == "HTTP":
        color = "http"

    else:
        color = "other"
    
    text.insert(tk.END, log + "\n", color)
    text.see(tk.END)

################### UPDATE GRAPH ###################

    graph_data.append(packet_count)

    if len(graph_data) > 20:
        graph_data.pop(0)

    update_graph()
    update_top_talkers()

################### SNIFF LOOP ###################

def sniff_loop():
    global running

    while running:
        sniff(iface="Wi-Fi", prn=process_packet, store = False, timeout = 1)

################### TOGGLE START/StoP ###################

def toggle_sniff():
    global running

    if not running:
        running = True

        toggle_btn.config(text="Stop", bg="red")

        thread = threading.Thread(target=sniff_loop)
        thread.daemon = True
        thread.start()

    else:
        running = False
        toggle_btn.config(text="Start", bg="green")

################### CLEAR ###################

def clear_text():
    global packet_count
    global graph_data

################### CLEAR TEXT ###################
    text.delete(1.0, tk.END)

################### PACKET RESET ###################
    packet_count = 0
    count_label.config(text="Packets: 0")

################### TOP TALKERS RESET ###################
    ip_counter.clear()
    talker_list.delete(0, tk.END)

################### GRAPH RESET ###################
    graph_data.clear()

    ax.clear()
    ax.set_title("Packets Over Time")

    canvas.draw()

################### SAVE TXT ###################

def save_txt():
    file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text File", "*.txt")])

    if not file:
        return
    
    with open(file, "w", encoding="utf-8") as f:
        for row in packet_logs:
            f.write(" | ".join(row) + "\n")

################### SAVE CSV ###################

def save_csv():
    file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV File", ".csv")])

    if not file:
        return
    
    with open(file, "w", newline="") as f:

        writer = csv.writer(f)
        
        writer.writerow(["Time", "Source", "Destination", "Protocol"])

        writer.writerows(packet_logs)

################### TOP TALKERS ###################

def update_top_talkers():

    talker_list.delete(0, tk.END)

    top = ip_counter.most_common(10)

    for i, (ip, count) in enumerate(top, start=1):
        talker_list.insert(tk.END, f"{i:>2}. {ip:<15}  {count:>4} pkt")

################### GRAPH ###################

def update_graph():
    ax.clear()
    ax.plot(graph_data)
    ax.set_title("Packets Over Time")
    canvas.draw()

################### GUI ###################

root = tk.Tk()

root.title("Mini WireShark")
root.geometry("1400x800")
root.configure(bg="#1e1e1e")

# root.iconbitmap("Guillendesign-Variations-2-Network.ico")

################### TOP FRAME ###################

top_frame = tk.Frame(root, bg="#1e1e1e")
top_frame.pack(fill="x", pady=5)

toggle_btn = tk.Button(top_frame, text="Start", bg="green", fg="white", width=10, command=toggle_sniff)
toggle_btn.pack(side="left", padx=5)

clear_btn = tk.Button(top_frame, text="Clear", command=clear_text)
clear_btn.pack(side="left", padx=5)

save_txt_btn = tk.Button(top_frame, text="Save TXT", command=save_txt)
save_txt_btn.pack(side="left", padx=5)

save_csv_btn = tk.Button(top_frame, text="Save CSV", command=save_csv)
save_csv_btn.pack(side="left", padx=5)

count_label = tk.Label(top_frame, text="Packets: 0", fg="white", bg="#1e1e1e", font=("Arial",12))
count_label.pack(side="left", padx=20)

################### PROTOCOL FILTER ###################

protocol_var = tk.StringVar(value="ALL")

protocol_menu = ttk.Combobox(top_frame, textvariable=protocol_var, values=["ALL", "TCP", "UDP", "HTTP"], width=10)
protocol_menu.pack(side="left", padx=10)

################### IP FILTER ###################

tk.Label(top_frame, text="IP Filter:", fg="white", bg="#1e1e1e").pack(side="left")

ip_entry = tk.Entry(top_frame, width=20)
ip_entry.pack(side="left", padx=5)

################### MAIN FRAME ###################

main_frame = tk.Frame(root)
main_frame.pack(fill="both", expand=True)

################### LEFT SIDE TEXT ###################

left_frame = tk.Frame(main_frame)
left_frame.pack(side="left", fill="both", expand=True)

scrollbar = tk.Scrollbar(left_frame)
scrollbar.pack(side="right", fill="y")

text = tk.Text(left_frame, bg="#111111", fg="white", insertbackground="white", font=("Consolas", 10), yscrollcommand=scrollbar.set)
text.pack(fill="both", expand=True)

scrollbar.config(command=text.yview)

################### COLORS ###################

text.tag_config("tcp", foreground="#00ff00")
text.tag_config("udp", foreground="#00bfff")
text.tag_config("http", foreground="#ff9900")
text.tag_config("other", foreground="white")

################### RIGHT PANEL ###################

right_panel = tk.Frame(main_frame, width=300, bg="#2a2a2a")
right_panel.pack(side="right", fill="y")

################### TOPTALKERS ###################

talker_label = tk.Label(right_panel, text="Top Talkers", bg="#2a2a2a", fg="white", font=("Arial", 12, "bold"))
talker_label.pack(pady=10)

talker_frame = tk.Frame(right_panel, bg="#2a2a2a")
talker_frame.pack(fill="x", padx=10, pady=5)

talker_scroll = tk.Scrollbar(talker_frame)
talker_scroll.pack(side="right", fill="y")

talker_list = tk.Listbox(talker_frame, bg="#111111", fg="#00ff99", font=("Consolas", 10), width=35, height=12, bd=0, highlightthickness=1, highlightbackground="#444444", yscrollcommand=talker_scroll.set)

talker_list.pack(side="left", fill="both", expand=True)

talker_scroll.config(command=talker_list.yview)

################### GRAPH ###################

fig = Figure(figsize=(4,3), dpi=100)

ax = fig.add_subplot(111)

canvas = FigureCanvasTkAgg(fig, master=right_panel)
canvas.get_tk_widget().pack(fill="both", expand=True)

root.mainloop()