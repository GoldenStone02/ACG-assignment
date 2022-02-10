# This script will be used to view the files located in the server.
# The file locations are in "source\server\data"

# Import the necessary libraries
# Used for getting the file path withn the server
from pathlib import Path


# Create a class for the GUI
class GUI:
    def __init__(self):
        '''
        Initialize the instance of the GUI class


        '''
        self.data_filepath = "source/server"
        self.files = []

    def run(self):
        '''
        This function will run the GUI and view the files in the server.
        '''
        self.files_in_dir()
        self.generate_UI()

    def files_in_dir(self):
        for child in Path(self.data_filepath).iterdir():
            if child.is_file():
                self.files.append(child)
    
    def generate_UI(self):
        '''
        This method will generate the UI for the user to view the files in the server.
        '''
        string = ""
        for file in self.files:
            # Prints out the file name on every line
            string += f"\n{file.name}"

        input(string)

    def validation(self, user_input):
        '''
        This method is used to validation that the user's input is valid.

        Parameters:
            user_input: The user's input

        Returns:
            True if the user's input is valid, False if not.
        '''
        if user_input == "":
            return False
        elif not user_input.isdigit():
            return False
        else:
            return True


    def get_files(self):
        pass


user_interface = GUI()
user_interface.run()