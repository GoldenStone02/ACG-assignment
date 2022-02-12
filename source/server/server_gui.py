# This script will be used to view the files located in the server.
# The file locations are in "source\server\data"

# Import the necessary libraries
import re
import getpass
from datetime import datetime
from Cryptodome.Hash import SHA256
# Used for getting the file path
from pathlib import Path
# Used to display the image
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
        self.empty = ""
        # Manages only the password
        self.password = "1Qwer$#@!"
        # Group 1: Camera ID, Group 2: Date, Group 3: Time
        self.PATTERN = r"(\d{2,3})_(\d{4}_\d{2}_\d{2})_(\d{2}_\d{2}_\d{2}).jpg"

    def run(self):
        '''
        This function will run the GUI and view the files in the server.
        '''
        while True:
            try:
                login_status = self.login()
            except KeyboardInterrupt:
                print(colors.fg.red, "\nTerminating Programme...", colors.fg.lightgrey)
            if login_status:    # If login was successful
                self.menu()

            elif login_status == False:
                break 

    def login(self):
        '''
        This method is used to login to the server.
        '''

        string = f"\n\t\tLog In\n{self.empty:-^80}\n{colors.fg.red}[ 0 ] Close Programme {colors.fg.lightgrey}\n{self.empty:-^80}\n>>> "
        while True:
            user_input = getpass.getpass(string)
            if user_input == "":
                print(colors.fg.red, "Invalid input.", colors.fg.lightgrey)
                continue
            if user_input == "0":
                print(colors.fg.red,"Terminating Programme...", colors.fg.lightgrey)
                return False
            elif self.validate_password(user_input):
                print("Password Correct!")
                return True
            else:
                print(colors.fg.red, "Invalid input.", colors.fg.lightgrey)
                continue

    def view_camera_data(self, camera_number, image_object):
        '''
        This method will be used to view the data of a given camera id.
        
        Args:
            ``camera_number``: The camera id being used to view the data.
            ``image_object``: The object that holds relevant image data.
        '''
        selected_camera_files = []
        files = []
        for file in image_object.files:
            data = re.search(self.PATTERN, file.name)
            if data.group(1) == str(camera_number):
                selected_camera_files.append(file)

                original_date = datetime.strptime(data.group(2), "%Y_%m_%d")
                date = original_date.strftime("%d/%m/%Y")
                original_time = datetime.strptime(data.group(3), "%H_%M_%S")
                time = original_time.strftime('%H:%M:%S')
                files.append(f"Date: {colors.fg.red}{date}{colors.fg.lightgrey}, Time: {colors.fg.blue}{time}{colors.fg.lightgrey}")
    
        menu = self.generate_ui(files, "Files")
        while True:
            user_input = self.validate_range(image_object.files, page=menu)
            if user_input == 0:
                break
            image_object.open_image(selected_camera_files[user_input - 1])


    def generate_ui(self, input_list: list = None, name: str = None):
        '''
        This method will generate the UI for the user when inputted a list.
        
        Args:
            ``input_list``: A list that will be used to generate a UI.
        '''

        string = f"\t\t{name}\n{self.empty:-^80}"
        # Sort smallers to largest
        input_list.sort(reverse=True)

        for i, file in enumerate(input_list):
            # Prints out the file name on every line
            string += f"\n[ {i + 1} ] {file}"
        string += f"\n{self.empty:-^80}\n[ 0 ] Back\n{self.empty:-^80}\n>>> "
        return string

    def menu(self):
        '''
        This method is used to display and navigate the menu.
        '''
        img_manager = ImageManager()
        # Gets a list of all camera ids data stored in the server
        camera_ids = img_manager.get_camera_ids()

        # Displays the camera ids for selection
        menu = self.generate_ui(camera_ids, "Camera IDs")
        while True:    
            user_input = self.validate_range(camera_ids, page=menu)
            if user_input == 0:
                break
            print("test")
            self.view_camera_data(camera_ids[user_input - 1], img_manager)
            
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
    
    def validate_range(self, input_list: list, page: str):
        '''
        This method checks if the input is within the range of the list.
        '''
        while True:
            try:
                check_input = int(input(page))
                if check_input < 0 or check_input > len(input_list):
                    raise OverflowError
                else:
                    return check_input
            except OverflowError:   # for out of range
                print('\33[41m' +f'Out of range! Please enter an integer number between 0 and {len(input_list)}'+ '\33[0m' +'\n')
            except ValueError:      # for not int number input 
                print('\33[41m'+ f'Invalid, not int. Please enter an integer number between 0 and {len(input_list)}'+'\33[0m' + '\n')


# Used to get the camera ids, and its files from the server
class ImageManager:
    '''
    This class is used to fetch the camera ids and the images from the server.
    '''
    def __init__(self):
        self.files = []
        self.camera_ids = []
        # Group 1: Camera ID, Group 2: Date, Group 3: Time
        self.PATTERN = r"(\d{2,3})_(\d{4}_\d{2}_\d{2})_(\d{2}_\d{2}_\d{2}).jpg"
        self.data_filepath = "source/server/data"

    def get_files(self):
        '''
        The method gets the data files from the path stated in `data_filepath`.
        '''
        for child in Path(self.data_filepath).iterdir():
            # Checks if the children are files and no in the self.files list.
            if child.is_file() and child not in self.files:
                self.files.append(child)

    def get_camera_ids(self) -> list:
        '''
        The method gets all the camera ids from the files in the server.

        Returns:
            ``self.camera_ids``: The list of camera ids.
        '''
        # Gets all the files in the 'data' folder from the server
        self.get_files()
        # Searchs through the entire folder of files.
        for camera in self.files:
            data = re.search(self.PATTERN, camera.name)
            # print("ID: ", data.group(1), ", Date: ", data.group(2), ", Time: ", data.group(3))
            if data.group(1) not in self.camera_ids:
                self.camera_ids.append(data.group(1))
            continue
        return self.camera_ids

    def open_image(self, image_path):
        '''
        This method opens an image using `Python Imaging Library`, `PIL`.
        '''
        img = Image.open(image_path)
        img.show()

user_interface = GUI()
user_interface.run()