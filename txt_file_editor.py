import os
import tkinter as tk
from tkinter import filedialog, messagebox

class FileManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Linux File Manager")
        self.root.geometry("700x700")
        self.root.configure(bg="#f0f0f0")

        self.title_label = tk.Label(self.root, text="Linux File Manager", font=("Arial", 20, "bold"), bg="#f0f0f0")
        self.title_label.pack(pady=20)

        self.dir_path_label = tk.Label(self.root, text="Current Directory: ", font=("Arial", 12), bg="#f0f0f0")
        self.dir_path_label.pack()

        self.current_dir = tk.StringVar()
        self.current_dir.set(os.getcwd())
        self.current_dir_label = tk.Label(self.root, textvariable=self.current_dir, font=("Arial", 12, "italic"), bg="#f0f0f0", fg="#0066cc")
        self.current_dir_label.pack(pady=5)

        frame = tk.Frame(self.root, bg="#f0f0f0")
        frame.pack(pady=10)

        self.file_listbox = tk.Listbox(frame, height=15, width=50, font=("Arial", 12), bd=0, selectmode=tk.SINGLE, bg="#ffffff", fg="#333333", relief="sunken")
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(frame, orient="vertical", command=self.file_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_listbox.config(yscrollcommand=scrollbar.set)

        button_frame = tk.Frame(self.root, bg="#f0f0f0")
        button_frame.pack(pady=20)

        self.refresh_button = tk.Button(button_frame, text="Refresh", command=self.refresh_directory, width=15, height=2, font=("Arial", 12), bg="#4CAF50", fg="white", relief="raised", bd=2)
        self.refresh_button.grid(row=0, column=0, padx=10, pady=5)

        self.change_dir_button = tk.Button(button_frame, text="Change Directory", command=self.change_directory, width=15, height=2, font=("Arial", 12), bg="#2196F3", fg="white", relief="raised", bd=2)
        self.change_dir_button.grid(row=0, column=1, padx=10, pady=5)

        self.create_file_button = tk.Button(button_frame, text="Create File", command=self.create_file, width=15, height=2, font=("Arial", 12), bg="#FFC107", fg="white", relief="raised", bd=2)
        self.create_file_button.grid(row=1, column=0, padx=10, pady=5)

        self.delete_file_button = tk.Button(button_frame, text="Delete File", command=self.delete_file, width=15, height=2, font=("Arial", 12), bg="#F44336", fg="white", relief="raised", bd=2)
        self.delete_file_button.grid(row=1, column=1, padx=10, pady=5)

        self.write_to_file_button = tk.Button(button_frame, text="Write to File", command=self.write_to_file, width=15, height=2, font=("Arial", 12), bg="#9C27B0", fg="white", relief="raised", bd=2)
        self.write_to_file_button.grid(row=2, column=0, padx=10, pady=5)

        self.view_file_button = tk.Button(button_frame, text="View File", command=self.view_file, width=15, height=2, font=("Arial", 12), bg="#607D8B", fg="white", relief="raised", bd=2)
        self.view_file_button.grid(row=2, column=1, padx=10, pady=5)

        self.refresh_directory()

    def refresh_directory(self):
        """Refresh the file list."""
        self.file_listbox.delete(0, tk.END)
        try:
            for file in os.listdir(self.current_dir.get()):
                self.file_listbox.insert(tk.END, file)
        except Exception as e:
            messagebox.showerror("Error", f"Could not refresh directory: {e}")

    def change_directory(self):
        """Open file dialog to change the current directory."""
        new_dir = filedialog.askdirectory(initialdir=self.current_dir.get(), title="Select a Directory")
        if new_dir:
            self.current_dir.set(new_dir)
            self.refresh_directory()

    def create_file(self):
        """Create a new file in the current directory."""
        file_name = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_name:
            try:
                with open(file_name, 'w') as f:
                    f.write("") 
                self.refresh_directory()
            except Exception as e:
                messagebox.showerror("Error", f"Could not create file: {e}")

    def delete_file(self):
        """Delete a file selected in the listbox."""
        selected_file = self.file_listbox.curselection()
        if selected_file:
            file_name = self.file_listbox.get(selected_file)
            file_path = os.path.join(self.current_dir.get(), file_name)
            confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete {file_name}?")
            if confirm:
                try:
                    os.remove(file_path)
                    self.refresh_directory()
                except Exception as e:
                    messagebox.showerror("Error", f"Could not delete file: {e}")
        else:
            messagebox.showwarning("No Selection", "Please select a file to delete.")

    def write_to_file(self):
        """Open a text editor to write to the selected file."""
        selected_file = self.file_listbox.curselection()
        if selected_file:
            file_name = self.file_listbox.get(selected_file)
            file_path = os.path.join(self.current_dir.get(), file_name)
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                write_window = tk.Toplevel(self.root)
                write_window.title(f"Write to {file_name}")
                write_window.geometry("600x400")

                text_box = tk.Text(write_window, height=15, width=70, font=("Arial", 12), wrap=tk.WORD)
                text_box.pack(padx=10, pady=10)
                text_box.insert(tk.END, content)

                def save_changes():
                    updated_content = text_box.get("1.0", tk.END).strip()
                    with open(file_path, 'w') as f:
                        f.write(updated_content)
                    messagebox.showinfo("Success", f"Changes saved to {file_name}")
                    write_window.destroy()
                    self.refresh_directory()

                save_button = tk.Button(write_window, text="Save Changes", command=save_changes, width=15, height=2, font=("Arial", 12), bg="#4CAF50", fg="white", relief="raised", bd=2)
                save_button.pack(pady=10)

            except Exception as e:
                messagebox.showerror("Error", f"Could not open file for writing: {e}")
        else:
            messagebox.showwarning("No Selection", "Please select a file to write to.")

    def view_file(self):
        """Open a new window to display file content in read-only mode."""
        selected_file = self.file_listbox.curselection()
        if selected_file:
            file_name = self.file_listbox.get(selected_file)
            file_path = os.path.join(self.current_dir.get(), file_name)
            try:
                with open(file_path, 'r') as f:
                    content = f.read()

                view_window = tk.Toplevel(self.root)
                view_window.title(f"View: {file_name}")
                view_window.geometry("600x400")

                text_box = tk.Text(view_window, height=15, width=70, font=("Arial", 12), wrap=tk.WORD)
                text_box.pack(padx=10, pady=10)
                text_box.insert(tk.END, content)
                text_box.config(state=tk.DISABLED) 
            except Exception as e:
                messagebox.showerror("Error", f"Could not open file: {e}")
        else:
            messagebox.showwarning("No Selection", "Please select a file to view.")



root = tk.Tk()
app = FileManagerApp(root)
root.mainloop()
