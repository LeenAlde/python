import sqlite3
import tkinter as tk
from tkinter import messagebox
import re
from random import randint
from tkinter import ttk
import bcrypt
import csv
from datetime import datetime

# --- Database Connection and Table Creation ---
conn = sqlite3.connect('KSUWorkshop.db')
c = conn.cursor()

# Create tables if they don't exist
c.execute('''
    CREATE TABLE IF NOT EXISTS stu (
        StuID TEXT PRIMARY KEY,
        FName TEXT,
        LName TEXT,
        Password TEXT,
        Email TEXT,
        mobileNo TEXT
    );
''')
c.execute('''
    CREATE TABLE IF NOT EXISTS workshop (
        eventID TEXT PRIMARY KEY,
        eventName TEXT,
        eventLoc TEXT,
        eventCap INTEGER,
        reservDate TEXT,
        reservTime TEXT
    );
''')
c.execute('''
    CREATE TABLE IF NOT EXISTS reservation (
        reservID TEXT PRIMARY KEY,
        StuID TEXT,
        eventID TEXT,
        FOREIGN KEY(StuID) REFERENCES stu(StuID),
        FOREIGN KEY(eventID) REFERENCES workshop(eventID)
    );
''')
conn.commit()
conn.close()

class GUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.geometry('400x200')
        self.root.title("KSU Workshop Reservation System")

        # Login Fields
        self.userVar = tk.StringVar()
        self.passwordVar = tk.StringVar()

        self.idLabel = tk.Label(self.root, text="ID :", width=20, font=("bold", 10))
        self.idLabel.place(x=0, y=60)
        self.idEntry = tk.Entry(self.root, textvariable=self.userVar)
        self.idEntry.place(x=170, y=60)

        self.usrLabel = tk.Label(self.root, text="Password :", width=20, font=("bold", 10))
        self.usrLabel.place(x=0, y=90)
        self.userEntry = tk.Entry(self.root, textvariable=self.passwordVar, show='*')
        self.userEntry.place(x=170, y=90)

        # Login Button
        login = tk.Button(self.root, text="Sign in", width=10, command=self.signin)
        login.place(x=120, y=130)

        # Signup Button
        signup = tk.Button(self.root, text="Sign up", width=10, command=self.signup)
        signup.place(x=220, y=130)

        # Create Admin Account
        self.create_admin_account()

        self.root.mainloop()

    def create_admin_account(self):
        conn = sqlite3.connect('KSUWorkshop.db')
        c = conn.cursor()
        admin_password = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt())
        c.execute("INSERT OR IGNORE INTO stu VALUES ('000000000', 'Admin', 'User', ?, 'admin@ksu.edu.sa', '0500000000')", (admin_password,))
        conn.commit()
        conn.close()

    def signup(self):
        self.signup_window = tk.Toplevel(self.root)
        self.signup_window.geometry('400x350')
        self.signup_window.title("Student Registration")

        tk.Label(self.signup_window, text="Student Registration", width=25, font=("bold", 22)).place(x=0, y=0)
        tk.Label(self.signup_window, text="StudentID:", width=17, font=("bold", 10)).place(x=50, y=80)
        self.entry_3 = tk.Entry(self.signup_window)
        self.entry_3.place(x=200, y=80)

        tk.Label(self.signup_window, text="First Name:", width=17, font=("bold", 10)).place(x=50, y=110)
        self.fNameEntry = tk.Entry(self.signup_window)
        self.fNameEntry.place(x=200, y=110)

        tk.Label(self.signup_window, text="Last Name:", width=17, font=("bold", 10)).place(x=50, y=140)
        self.INameEntry = tk.Entry(self.signup_window)
        self.INameEntry.place(x=200, y=140)

        tk.Label(self.signup_window, text="Password:", width=17, font=("bold", 10)).place(x=50, y=170)
        self.passEntry = tk.Entry(self.signup_window)
        self.passEntry.place(x=200, y=170)

        tk.Label(self.signup_window, text="Email address:", width=17, font=("bold", 10)).place(x=50, y=200)
        self.emailEntry = tk.Entry(self.signup_window)
        self.emailEntry.place(x=200, y=200)

        tk.Label(self.signup_window, text="Phone number:", width=17, font=("bold", 10)).place(x=50, y=230)
        self.mobileEntry = tk.Entry(self.signup_window)
        self.mobileEntry.place(x=200, y=230)

        tk.Button(self.signup_window, text='Save', width=20, command=self.saveStulnf).place(x=120, y=280)

    def saveStulnf(self):
        try:
            conn = sqlite3.connect('KSUWorkshop.db')
            c = conn.cursor()
            StuID = self.entry_3.get()
            firstname = self.fNameEntry.get()
            lastname = self.INameEntry.get()
            password = self.passEntry.get()
            email = self.emailEntry.get()
            mobile = self.mobileEntry.get()

            # Input Validation
            if not re.match(r"^\d{9}$", StuID):
                messagebox.showinfo("Invalid input", "Student ID must be 9 digits")
                conn.close()
                return
            if not firstname or not lastname:
                messagebox.showinfo("Invalid input", "First name and last name cannot be empty")
                conn.close()
                return
            if not re.match(r"^[A-Za-z0-9]{6,}$", password):
                messagebox.showinfo("Invalid input", "Password must be at least 6 characters")
                conn.close()
                return
            if not re.match(r"^[a-zA-Z0-9._%+-]+@student\.ksu\.edu\.sa$", email):
                messagebox.showinfo("Invalid input", "Invalid email format")
                conn.close()
                return
            if not re.match(r"^(05)\d{8}$", mobile):
                messagebox.showinfo("Invalid input", "Invalid mobile number format")
                conn.close()
                return

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            c.execute("SELECT StuID FROM stu WHERE StuID = ?", (StuID,))
            if c.fetchone():
                messagebox.showinfo("Error", "Student ID already exists")
                conn.close()
                return

            c.execute("INSERT INTO stu VALUES (?, ?, ?, ?, ?, ?)", (StuID, firstname, lastname, hashed_password, email, mobile))
            conn.commit()
            messagebox.showinfo("Success", "Student registered successfully")
            conn.close()

        except sqlite3.Error as e:
            messagebox.showinfo("Database error", f"Database ERROR: {e}")
        except Exception as e:
            messagebox.showinfo("Error", f"An unexpected error occurred: {e}")

    def signin(self):
        try:
            conn = sqlite3.connect('KSUWorkshop.db')
            c = conn.cursor()
            uid = self.userVar.get()
            pwd = self.passwordVar.get()

            if not re.match(r"^\d{9}$", uid):
                messagebox.showinfo("Invalid ID", "ID must be 9 digits")
                conn.close()
                return

            c.execute("SELECT Password FROM stu WHERE StuID = ?", (uid,))
            user_data = c.fetchone()
            conn.close()

            if user_data:
                hashed_password = user_data[0]
                if bcrypt.checkpw(pwd.encode('utf-8'), hashed_password):
                    messagebox.showinfo("Success", "Login Successful")
                    if uid == "000000000":
                        self.root.withdraw()
                        self.adminWindow()
                    else:
                        self.root.withdraw()
                        self.bookingTickitsWindow(uid)
                else:
                    messagebox.showinfo("Error", "Incorrect password")
            else:
                messagebox.showinfo("Error", "User not found")

        except sqlite3.Error as e:
            messagebox.showinfo("Database error", f"Database ERROR: {e}")
        except Exception as e:
            messagebox.showinfo("Error", f"An unexpected error occurred: {e}")

    def adminWindow(self):
        self.admin_window = tk.Toplevel(self.root)
        self.admin_window.geometry('500x400')
        self.admin_window.title("Admin Panel")

        tk.Label(self.admin_window, text="Workshop Name:").pack()
        self.workshopName = tk.Entry(self.admin_window)
        self.workshopName.pack()

        tk.Label(self.admin_window, text="Workshop Location:").pack()
        self.workshopLocation = tk.Entry(self.admin_window)
        self.workshopLocation.pack()

        tk.Label(self.admin_window, text="Workshop Capacity:").pack()
        self.workshopCapacity = tk.Entry(self.admin_window)
        self.workshopCapacity.pack()

        tk.Label(self.admin_window, text="Date & Time (YYYY-MM-DD HH:MM):").pack()
        self.workshopDateTime = tk.Entry(self.admin_window)
        self.workshopDateTime.pack()

        tk.Button(self.admin_window, text="Create Workshop", command=self.createWorkshop).pack()
        tk.Button(self.admin_window, text="Backup Data", command=self.backupData).pack()
        tk.Button(self.admin_window, text="Logout", command=self.logout)
        tk.Button(self.admin_window, text="Logout", command=self.logout).pack()

    def createWorkshop(self):
        try:
            workshop_id = str(randint(10000, 99999))
            name = self.workshopName.get()
            location = self.workshopLocation.get()
            capacity = int(self.workshopCapacity.get())
            date, time = self.workshopDateTime.get().split()

            conn = sqlite3.connect('KSUWorkshop.db')
            c = conn.cursor()
            c.execute("INSERT INTO workshop VALUES (?, ?, ?, ?, ?, ?)", (workshop_id, name, location, capacity, date, time))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", "Workshop created successfully")
        except Exception as e:
            messagebox.showinfo("Error", f"Failed to create workshop: {e}")

    def backupData(self):
        try:
            conn = sqlite3.connect('KSUWorkshop.db')
            c = conn.cursor()
            c.execute("SELECT * FROM workshop")
            data = c.fetchall()
            conn.close()

            with open('backup.csv', 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Workshop ID", "Name", "Location", "Capacity", "Date", "Time"])
                writer.writerows(data)

            messagebox.showinfo("Success", "Data backed up successfully")
        except Exception as e:
            messagebox.showinfo("Error", f"Failed to backup data: {e}")

    def bookingTickitsWindow(self, uid):
        self.booking_window = tk.Toplevel(self.root)
        self.booking_window.geometry('700x400')
        self.booking_window.title("Booking Workshops")

        self.notebook = ttk.Notebook(self.booking_window)
        self.notebook.pack(pady=10, expand=True)

        self.frame1 = ttk.Frame(self.notebook, width=500, height=200)
        self.frame2 = ttk.Frame(self.notebook, width=500)

        self.notebook.add(self.frame1, text="Book a Workshop")
        self.notebook.add(self.frame2, text="View My Workshops")

        self.displayWorkshops(self.frame1)
        self.displayBookedWorkshops(self.frame2, uid)

        tk.Button(self.booking_window, text='Logout', width=10, bg='AntiqueWhite3', fg='black', command=self.logout).place(x=300, y=350)

    def displayWorkshops(self, frame):
        try:
            conn = sqlite3.connect('KSUWorkshop.db')
            c = conn.cursor()
            workshops = c.execute("SELECT * FROM workshop")
            workshop_data = workshops.fetchall()
            conn.close()

            self.workshopListbox = tk.Listbox(frame, width=50, height=10)
            self.workshopListbox.pack(pady=10)

            for workshop in workshop_data:
                workshop_info = f"ID: {workshop[0]}, Name: {workshop[1]}, Location: {workshop[2]}, Capacity: {workshop[3]}, Date: {workshop[4]}, Time: {workshop[5]}"
                self.workshopListbox.insert(tk.END, workshop_info)

            tk.Button(frame, text='Book', width=10, bg='AntiqueWhite3', fg='black', command=lambda: self.bookWorkshop(self.workshopListbox.get(tk.ANCHOR))).pack()

        except Exception as e:
            messagebox.showinfo("Error", f"Failed to display workshops: {e}")

    def displayBookedWorkshops(self, frame, uid):
        try:
            conn = sqlite3.connect('KSUWorkshop.db')
            c = conn.cursor()
            booked_workshops = c.execute(f"SELECT w.eventName, w.eventLoc, w.reservDate, w.reservTime FROM reservation r JOIN workshop w ON r.eventID = w.eventID WHERE r.StuID = ?", (uid,))
            booked_data = booked_workshops.fetchall()
            conn.close()

            self.bookedListbox = tk.Listbox(frame, width=50, height=10)
            self.bookedListbox.pack(pady=10)

            for workshop in booked_data:
                workshop_info = f"Name: {workshop[0]}, Location: {workshop[1]}, Date: {workshop[2]}, Time: {workshop[3]}"
                self.bookedListbox.insert(tk.END, workshop_info)

        except Exception as e:
            messagebox.showinfo("Error", f"Failed to display booked workshops: {e}")

    def bookWorkshop(self, workshop_info):
        try:
            conn = sqlite3.connect('KSUWorkshop.db')
            c = conn.cursor()

            workshop_id = workshop_info.split(",")[0].split(":")[1].strip()

            existing_reservation = c.execute("SELECT * FROM reservation WHERE StuID = ? AND eventID = ?", (self.userVar.get(), workshop_id))
            if existing_reservation.fetchone():
                messagebox.showinfo("Error", "You have already booked this workshop.")
                conn.close()
                return

            capacity = c.execute("SELECT eventCap FROM workshop WHERE eventID = ?", (workshop_id,))
            current_capacity = capacity.fetchone()[0]
            if current_capacity == 0:
                messagebox.showinfo("Error", "This workshop is fully booked.")
                conn.close()
                return

            reservID = str(randint(10000, 99999))
            c.execute("INSERT INTO reservation VALUES(?, ?, ?)", (reservID, self.userVar.get(), workshop_id))
            c.execute("UPDATE workshop SET eventCap = eventCap - 1 WHERE eventID = ?", (workshop_id,))
            conn.commit()
            messagebox.showinfo("Success", "Workshop booked successfully.")
            conn.close()

            self.workshopListbox.delete(0, tk.END)
            self.displayWorkshops(self.frame1)

            self.bookedListbox.delete(0, tk.END)
            self.displayBookedWorkshops(self.frame2, self.userVar.get())

        except Exception as e:
            messagebox.showinfo("Error", f"Failed to book workshop: {e}")

    def logout(self):
        self.booking_window.destroy()
        self.root.destroy()

if __name__ == "__main__":
    gui = GUI()

