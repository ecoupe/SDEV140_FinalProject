from breezypythongui import EasyFrame
from tkinter import messagebox, IntVar, PhotoImage, Label, Toplevel, Button, Text, Scrollbar, RIGHT, Y, END
from tkinter.ttk import Combobox
import random

class PasswordManagerGenerator(EasyFrame):
    """
    A GUI-based application for managing usernames and passwords. 
    Users can add, retrieve, display, delete, and generate passwords.
    """

    def __init__(self):
        """
        Initializes the main application window with input fields, buttons,
        and a password generation section.
        """
        # Initialize the main window
        EasyFrame.__init__(self, title="Soapbox Password Manager & Generator", width=600, height=550)

        # Input fields for description, username, and password
        self.addLabel(text="DESCRIPTION:", row=1, column=0, sticky="w")  # Label for description field
        self.descriptionField = self.addTextField(text="", row=1, column=1, columnspan=2, sticky="we")  # Input field for description
        
        self.addLabel(text="USERNAME:", row=2, column=0, sticky="w")  # Label for username field
        self.usernameField = self.addTextField(text="", row=2, column=1, columnspan=2, sticky="we")  # Input field for username
        
        self.addLabel(text="PASSWORD:", row=3, column=0, sticky="w")  # Label for password field
        self.passwordField = self.addTextField(text="", row=3, column=1, columnspan=2, sticky="we")  # Input field for password

        # Action buttons
        self.addButton(text="Add", row=4, column=0, command=self.add_password)  # Add a password
        self.addButton(text="Get", row=4, column=1, command=self.retrieve_password)  # Retrieve a password
        self.addButton(text="List", row=4, column=2, command=self.display_password_list)  # List all passwords
        self.addButton(text="Delete", row=4, column=3, command=self.delete_password)  # Delete a password

        # Password generator section
        self.addLabel(text="PASSWORD GENERATOR", row=5, column=0, columnspan=4, sticky="w")  # Section title
        self.addLabel(text="Generated Password:", row=6, column=0)  # Label for generated password field
        self.generatedPasswordField = self.addTextField(text="", row=6, column=1, columnspan=2, sticky="we")  # Display for generated password
        
        # Dropdown for selecting password length
        self.addLabel(text="Length:", row=7, column=0)  # Label for password length combobox
        self.passwordLength = IntVar()  # Variable to store selected password length
        self.comboLength = Combobox(self, textvariable=self.passwordLength, width=10)  # Combobox for password length
        self.comboLength['values'] = tuple(range(12, 37))  # Length options (12-36 characters)
        self.comboLength.current(0)  # Set default length to 12
        self.comboLength.grid(row=7, column=1, sticky="w")

        # Button to generate a random password
        self.addButton(text="Generate", row=7, column=2, command=self.generate_password)

        # Logo at the top of the window
        self.logo = PhotoImage(file="SPMG_logo.gif").subsample(4, 4)  # Load and resize logo
        self.logoLabel = Label(self, image=self.logo)  # Label to display the logo
        self.logoLabel.grid(row=0, column=0, columnspan=4, sticky="n")

    def generate_password(self):
        """
        Generates a random password using uppercase, lowercase, digits, and special characters.
        Displays the password in the password field and the generated password field.
        """
        length = int(self.comboLength.get())  # Get selected password length
        characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()"  # Character set for passwords
        password = ''.join(random.choice(characters) for _ in range(length))  # Generate password
        self.generatedPasswordField.setText(password)  # Display the password
        self.passwordField.setText(password)  # Set the generated password in the input field

    def add_password(self):
        """
        Adds the entered description, username, and password to the file for storage.
        Shows a success or error message based on the operation result.
        """
        description = self.descriptionField.getText()  # Get entered description
        username = self.usernameField.getText()  # Get entered username
        password = self.passwordField.getText()  # Get entered password

        if not description or not username or not password:  # Check for empty fields
            messagebox.showerror("Error", "Please enter a Description, Username, and Password.")
            return

        # Append the description, username, and password to the file
        try:
            with open("soapboxes_galore.txt", 'a') as file:
                file.write(f"{description} {username} {password}\n")  # Save description, username, and password
            messagebox.showinfo("Success", "Information added successfully!")  # Success message
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save information: {e}")  # Error message

    def retrieve_password(self):
        """
        Retrieves and displays the information for the entered username.
        """
        username = self.usernameField.getText()  # Get entered username
        descriptions = self._read_password_file()  # Read all stored information

        if not descriptions:  # If no information is found
            messagebox.showinfo("Info", "No information found.")
            return

        description = descriptions.get(username)  # Get the information for the entered username
        if description:
            self._show_custom_window("Retrieve Information", f"{description} for {username}", "SB_pile.gif")
        else:
            messagebox.showinfo("Info", "Username not found.")

    def display_password_list(self):
        """
        Displays the full list of descriptions, usernames, and passwords in a new window.
        """
        descriptions = self._read_password_file()  # Read all stored information

        if not descriptions:  # If no information is found
            messagebox.showinfo("Info", "No information found.")
            return

        # Format the information list as a string
        information_list = "\n".join([f"{desc} for Username: {user}" for user, desc in descriptions.items()])
        self._show_custom_window("Information List", f"List of information:\n\n{information_list}", "SB_pile.gif")

    def delete_password(self):
        """
        Deletes the information for the entered username from the file.
        """
        username = self.usernameField.getText()  # Get entered username
        descriptions = self._read_password_file()  # Read all stored information

        if username not in descriptions:  # Check if username exists
            messagebox.showerror("Error", "Username not found.")
            return

        # Remove the username from the information dictionary
        del descriptions[username]
        self._write_password_file(descriptions)  # Write the updated information back to the file
        messagebox.showinfo("Success", f"Information for {username} deleted.")  # Success message

    def _show_custom_window(self, title, message, image_file):
        """
        Creates and displays a custom dialog with an image and a message.
        Args:
            title (str): The title of the window.
            message (str): The message to display in the window.
            image_file (str): The path to the image to display.
        """
        dialog = Toplevel(self)  # Create a new dialog window
        dialog.title(title)  # Set the title of the window
        dialog.geometry("500x400")  # Set the window size

        # Add image
        try:
            dialog_image = PhotoImage(file=image_file).subsample(3, 3)  # Load and resize image
            image_label = Label(dialog, image=dialog_image)
            image_label.image = dialog_image  # Keep a reference to prevent garbage collection
            image_label.pack()
        except Exception:
            Label(dialog, text="Image could not be loaded.").pack()  # Fallback if image fails to load

        # Add a text widget for the message
        text_widget = Text(dialog, wrap="word")
        text_widget.insert(1.0, message)
        text_widget.config(state="disabled")  # Make the text read-only
        text_widget.pack(pady=10, fill="both", expand=True)

        # Add a scrollbar to the text widget
        scrollbar = Scrollbar(dialog, command=text_widget.yview)
        text_widget.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=RIGHT, fill=Y)

        # Add a close button
        Button(dialog, text="OK", command=dialog.destroy).pack(pady=5)

    def _read_password_file(self):
        """
        Reads the information file and returns a dictionary of usernames and their information.
        Returns:
            dict: A dictionary where keys are usernames and values are descriptions and passwords.
        """
        descriptions = {}
        try:
            with open("soapboxes_galore.txt", 'r') as file:
                for line in file:
                    parts = line.strip().split(' ', 2)  # Split into description, username, and password
                    if len(parts) == 3:
                        descriptions[parts[1]] = f"Description: {parts[0]}, Password: {parts[2]}"
        except FileNotFoundError:
            pass  # File does not exist yet
        return descriptions

    def _write_password_file(self, descriptions):
        """
        Writes the updated dictionary of descriptions and passwords to the file.
        Args:
            descriptions (dict): The dictionary of descriptions and passwords to save.
        """
        try:
            with open("soapboxes_galore.txt", 'w') as file:
                for username, description in descriptions.items():
                    parts = description.split(", Password: ")
                    file.write(f"{parts[0].replace('Description: ', '')} {username} {parts[1]}\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update information file: {e}")  # Error message


def main():
    """
    Runs the Password Manager application.
    """
    PasswordManagerGenerator().mainloop()


if __name__ == "__main__":
    main()
