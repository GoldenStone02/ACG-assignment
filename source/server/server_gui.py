# This script will be used to view the files located in the server.
# The file locations are in "source\server\data"

# Import the necessary libraries
# Used for getting the file path withn the server
from pathlib import Path
# Used to show the image
from PIL import Image

# Python program to print
# colored text and background
class colors:
    '''
    Colors class:reset all colors with colors.reset; two
    sub classes fg for foreground
    and bg for background; use as colors.subclass.colorname.
    i.e. colors.fg.red or colors.bg.greenalso, the generic bold, disable,
    underline, reverse, strike through,
    and invisible work with the main class i.e. colors.bold
    '''
    reset='\033[0m'
    bold='\033[01m'
    disable='\033[02m'
    underline='\033[04m'
    reverse='\033[07m'
    strikethrough='\033[09m'
    invisible='\033[08m'
    class fg:
        black='\033[30m'
        red='\033[31m'
        green='\033[32m'
        orange='\033[33m'
        blue='\033[34m'
        purple='\033[35m'
        cyan='\033[36m'
        lightgrey='\033[37m'
        darkgrey='\033[90m'
        lightred='\033[91m'
        lightgreen='\033[92m'
        yellow='\033[93m'
        lightblue='\033[94m'
        pink='\033[95m'
        lightcyan='\033[96m'
    class bg:
        black='\033[40m'
        red='\033[41m'
        green='\033[42m'
        orange='\033[43m'
        blue='\033[44m'
        purple='\033[45m'
        cyan='\033[46m'
        lightgrey='\033[47m'

# Create a class for the GUI
class GUI:
    def __init__(self):
        '''
        Initialize the instance of the GUI class
        '''
        self.password = "1Qwer$#@!"
        self.data_filepath = "source/server"
        self.files = []
        self.camera_ids = []
        self.PATTERN = "(\d)_*.jpg"

    def run(self):
        '''
        This function will run the GUI and view the files in the server.
        '''
        self.get_files_in_dir()     # Get the data files in the server
        self.get_all_camera_id()    # Get all the different camera ids in the server
        try:
            login_status = self.login()
        except KeyboardInterrupt:
            print(colors.fg.red, "\nTerminating Programme...", colors.fg.lightgrey)
        if login_status:    # If login was successful
            self.menu()

    def get_files_in_dir(self):
        '''
        The method gets the data files from the "/server/data/" directory.
        '''
        for child in Path(self.data_filepath).iterdir():
            if child.is_file():
                self.files.append(child)

    def login(self):
        '''
        This method is used to login to the server.
        '''
        empty = ""

        string = f"\n\t\tLog In\n{empty:-^80}\n{colors.fg.red}[ 0 ] Close Programme {colors.fg.lightgrey}\n{empty:-^80}\n>>> "
        while True:
            user_input = input(string)
            if user_input == "":
                print(colors.fg.red, "Invalid input.", colors.fg.lightgrey)
                continue
            if user_input == "0":
                print(colors.fg.red,"Terminating Programme...", colors.fg.lightgrey)
                return False
            elif self.validate_password(user_input):
                print("correct")
                return True
            else:
                print(colors.fg.red, "Invalid input.", colors.fg.lightgrey)
                continue

    def menu(self):
        '''
        This method is used to display and navigate the menu.
        '''
        menu_page = self.generate_ui()
        while True:    
            user_input = input(menu_page)
            if user_input == "":
                break

    def get_all_camera_id(self):
        for camera in self.files:
            if camera.name.group(1) not in self.camera_ids:
                self.camera_ids.append(camera.name.group(1))
            continue

    def generate_ui(self):
        '''
        This method will generate the UI for the user to view the files in the server.
        '''
        string = ""
        for i, file in enumerate(self.files):
            # Prints out the file name on every line
            string += f"\n[ {i + 1} ]{file.name}"
        return string

    def validate_password(self, user_input):
        '''
        This method is used to validate the password.

        Parameters:
            user_input: The user's input
        '''
        if user_input == self.password:
            return True
        else:
            return False

    def open_image(self, image_path):
        img = Image.open(image_path)
        img.show()


user_interface = GUI()
user_interface.run()