/*
Student Author: Min Htut Myat
Student Number: 7058949
Subject: CSCI262 Systems Security

Assignment 1 Part Two
*/

#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <termios.h>
#include <unistd.h>
#include "md5.h"
#include "FileSystem.h"
//#include <openssl/md5.h>
#include <time.h>
#include <random>
#include <regex>
#include <vector>

std::string inputusername;
std::string Fileclearance;
bool presentinfile = false;

void Initialize()
{
    std::string password;
    std::string cfmpassword;
    int clearance;

    std::cout << "Username: ";
    std::cin >> inputusername;

    // Read users for checking
    std::ifstream checkfile("shadow.txt"); //NOTE: This is considered as opening the file

    std::string line;

    // File error check sequences
    if(checkfile.eof())
    {
        std::cerr << " End of file reached " << std::endl;
        exit(-1);
    }
    else if(!checkfile.is_open())
    {
        std::cerr << " Error opening file " << std::endl;
        exit(-1);
    }
    else if(checkfile.fail())
    {
        std::cerr << " File contains invalid data" << std::endl;
        exit(-1);
    }
    else if(checkfile.bad())
    {
        std::cerr << " Read and write error in program logic " << std::endl;
        exit(-1);
    }
    
    while(getline(checkfile, line))
    {
       if(line.find(inputusername) != std::string::npos)
       {
          std::cout << "User already exists, Terminating program..." << std::endl;
          exit(0);
       }
       // else break will not complete the loop checking until end of file
    }

    checkfile.close(); // Important to close file after every read or write operation or else bugs to debug

    // Hide password input on program runtime for password
    termios show;
    tcgetattr(STDIN_FILENO, &show);
    termios hide = show;
    hide.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &hide); 

    std::cout << "Password: ";
    std::cin >> password;
    std::cout << std::endl;
    std::cout << "Confirm Password: ";
    std::cin >> cfmpassword;
    std::cout << std::endl;

    // Check password strength
    std::regex passstrengthpattern("(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@#$%^&+=])(?=\\S+$).{10,}");

    if(!regex_match(password,passstrengthpattern))
    {
        std::cout << "Insufficient Password Strength"<< std::endl;
        std::cout << std::endl;
        std::cout << "Password must have: "<< std::endl;
        std::cout << "At least 10 characters long" << std::endl;
        std::cout << "At least 1 uppercase character" << std::endl;
        std::cout << "At least 1 lowercase character" << std::endl;
        std::cout << "At least 1 number" << std::endl;
        std::cout << "At least 1 special character" << std::endl;
        std::cout << "Exiting... " << std::endl;
        exit(0);
    }

    if(password != cfmpassword)
    {
        // Loop here for 3 times to re-enter
        for (int i = 0; i < 3; i++)
        {
           std::cout << "Confirm Password: ";
           std::cin >> cfmpassword;
           std::cout << std::endl;

           if(password == cfmpassword)
           {
              break;
           }
           else if(i == 2)
           {
              std::cout << "Maximum 3 password retries reached. Exiting...";
              exit(0);
           }
        }
    }

    // Handle salting and hashing and transfer user details to .txt file
    std::string salt;
    std::string passwordhash;

    // randomizer for salt length
    srand(time(0));
    std::string charsaltset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int saltLength = rand() % (20 - 12) + 12;

    std::random_device unidist;
    std::mt19937 eng(unidist());
    std::uniform_int_distribution<> dist(0, charsaltset.size() -1);

    for (int i = 0; i < saltLength; i++)
    {
        salt += charsaltset[dist(eng)];
    }

    // Debug statement, passed
    // std::cout << salt << std::endl;

    passwordhash = password + salt;

    std::string saltedhash = md5(passwordhash);

    // switch to show back input again
    tcsetattr(STDIN_FILENO, TCSANOW, &show); 

    std::cout << "User clearance (0 or 1 or 2 or 3): ";
    std::cin >> clearance;
    std::cout << std::endl;

    // Write into shadow and salt file
    std::ofstream writefileshadow("shadow.txt",std::ios::app); // APPEND not write, write will overwrite

    writefileshadow << inputusername << ":" << saltedhash << ":" << clearance << std::endl;

    writefileshadow.close(); // Important to close file after every read and write operation.

    std::ofstream writefilesalt("salt.txt", std::ios::app); // APPEND not write, write will overwrite

    writefilesalt << inputusername << ":" << salt << std::endl;

    writefilesalt.close(); // Important to close file after every read and write operation.

    std::cout << "Initialization completed successfully..." << std::endl;   

    // std::cout << "BEEP BOOPING goes here" << std::endl;
}

void Login_Authentication()
{
    // Reset Condition
    presentinfile = false;
    std::string password;
    std::cout << "Username: ";
    std::cin >> inputusername; 

    // Read salt to extract salt for secure login
    std::ifstream readfilesalt("salt.txt"); //NOTE: This is considered as opening the file

    std::string line;

    // File error check sequences
    if(readfilesalt.eof())
    {
        std::cerr << " End of file reached " << std::endl;
        exit(-1);
    }
    else if(!readfilesalt.is_open())
    {
        std::cerr << " Error opening file " << std::endl;
        exit(-1);
    }
    else if(readfilesalt.fail())
    {
        std::cerr << " File contains invalid data" << std::endl;
        exit(-1);
    }
    else if(readfilesalt.bad())
    {
        std::cerr << " Read and write error in program logic " << std::endl;
        exit(-1);
    }
    
    std::string user,salt;

    while(getline(readfilesalt, line))
    {
       if(line.find(inputusername) != std::string::npos)
       {

          std::stringstream textstream(line);
          getline(textstream,user,':');
          getline(textstream,salt,':');
          presentinfile = true;
          break;
       }
       // Continue to loop until match is found else user does not exist
    }

    switch(presentinfile)
    {
       case false:
          std::cout << "User does not exist, Terminating program..." << std::endl;
          exit(0);
    }

    readfilesalt.close();

    // Hide password input on program runtime
    termios show;
    tcgetattr(STDIN_FILENO, &show);
    termios hide = show;
    hide.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &hide); 

    std::cout << "Password: ";
    std::cin >> password;
    std::cout << std::endl;

    // As required by Assignment specifications
    std::cout << inputusername << " found in salt.txt" << std::endl;
    std::cout << "salt retrieved: " << salt << std::endl;
    std::cout << "hashing..." << std::endl;
   
    // Read hash to extract hash for secure login
    std::ifstream readfileshadow("shadow.txt"); //NOTE: This is considered as opening the file

    std::string line2; 

    // File error check sequences
    if(readfileshadow.eof())
    {
        std::cerr << " End of file reached " << std::endl;
        exit(-1);
    }
    else if(!readfileshadow.is_open())
    {
        std::cerr << " Error opening file " << std::endl;
        exit(-1);
    }
    else if(readfileshadow.fail())
    {
        std::cerr << " File contains invalid data" << std::endl;
        exit(-1);
    }
    else if(readfileshadow.bad())
    {
        std::cerr << " Read and write error in program logic " << std::endl;
        exit(-1);
    }
    
    // Reset condition to check again
    presentinfile = false;
    std::string userS,passhash,accesslevel; 

    while(getline(readfileshadow, line2))
    {
       if(line2.find(inputusername) != std::string::npos)
       {
          std::stringstream textstream2(line2);
          getline(textstream2,userS,':');
          getline(textstream2,passhash,':');
          getline(textstream2,accesslevel,':');
          presentinfile = true;
          break;
       }
       // Continue to loop until match is found else user does not exist
    }

    switch(presentinfile)
    {
       case false:
          std::cout << "User does not exist, Terminating program..." << std::endl;
          exit(0);
    }

    readfileshadow.close();

    // Hash verification for login
    std::string inputpasshash = password + salt;
    inputpasshash = md5(inputpasshash);

    // Debug statement to check hashes (passed)
    // std::cout << inputpasshash << " vs " << passhash << std::endl;
    // switch to show back again
    tcsetattr(STDIN_FILENO, TCSANOW, &show); 

    // if resulthash from input is equal to hash in shadow.txt, login is successfull
    if(inputpasshash == passhash)
    {
        std::cout << "Authentication for user " << inputusername << " complete." << std::endl;
        std::cout << "The clearance for " << inputusername << " is " << accesslevel << std::endl;
        Fileclearance = accesslevel;
        Filesystem();
    }
    else
    {
        std::cout << "Wrong Credentials, Exiting..." << std::endl;
        exit(0);
    }

}

void FileSystemMenu()
{
    std::cout << std::endl;
    std::cout << "Options: (C)reate, (A)ppend, (R)ead, (W)rite, (L)ist, (S)ave or (E)xit." << std::endl;
    std::cout << "Input your choice of operation: ";
}

void Filesystem()
{
    char operation; 
    bool exited = false;

    // When the User is not finished or some validation errors, redisplay the menu again
    // Infinite loop to facilitate menu redisplay, case Exit with exit the program
    while(!exited)
    {
        FileSystemMenu();
        std::cin >> operation; 
        // std::cout << std::endl;

        // For File operations defined as per assignment requirements
        switch (operation)
        {
            // Create
            case 'C':  {
                std::string Filename;
                std::cout << "Filename: ";
                std::cin >> Filename;

                std::ifstream chkfile("Files.store");

                // File error check sequences
                if(chkfile.eof())
                {
                    std::cerr << " End of file reached " << std::endl;
                    exit(-1);
                }
                else if(!chkfile.is_open())
                {
                    std::cerr << " Error opening file " << std::endl;
                    exit(-1);
                }
                else if(chkfile.fail())
                {
                    std::cerr << " File contains invalid data" << std::endl;
                    exit(-1);
                }
                else if(chkfile.bad())
                {
                    std::cerr << " Read and write error in program logic " << std::endl;
                    exit(-1);
                }

                std::string line;

                while(getline(chkfile, line))
                {
                    if(line.find(Filename) != std::string::npos)
                    {
                        // No creation of existing file
                        std::cout<< "Error: Cannot create file that already exists" << std::endl;
                        presentinfile = true;
                        break;
                    }
                    else
                    {
                        presentinfile = false;
                    }
                }

                // When file does not exist
                if(presentinfile == false)
                {
                    // Create file
                    std::ofstream createfile(Filename + ".txt");
                    createfile.close();

                    // Write to Files.store
                    std::ofstream writefilestore("Files.store", std::ios::app); 
                    writefilestore << Filename << ":" << inputusername << ":" << Fileclearance << std::endl;
                    writefilestore.close();
                    std::cout << "File creation successful..." << std::endl;
                }
                chkfile.close();
                break;
            }
            // Append
            case 'A':{
                std::string Filename;
                std::cout << "Filename: ";
                std::cin >> Filename;

                std::ifstream chkfile("Files.store");

                // File error check sequences
                if(chkfile.eof())
                {
                    std::cerr << " End of file reached " << std::endl;
                    exit(-1);
                }
                else if(!chkfile.is_open())
                {
                    std::cerr << " Error opening file " << std::endl;
                    exit(-1);
                }
                else if(chkfile.fail())
                {
                    std::cerr << " File contains invalid data" << std::endl;
                    exit(-1);
                }
                else if(chkfile.bad())
                {
                    std::cerr << " Read and write error in program logic " << std::endl;
                    exit(-1);
                }

                std::string line;
                std::string file,user,accesslevel;
                while(getline(chkfile, line))
                {
                    if(line.find(Filename) != std::string::npos)
                    {
                        std::stringstream textstream(line);
                        getline(textstream,file,':');
                        getline(textstream,user,':');
                        getline(textstream,accesslevel,':');
                        presentinfile = true;
                        break; // break for when we find a match and proceed on 
                    }
                    else
                    {
                        presentinfile = false;
                    }
                }
                chkfile.close();

                // When file exists
                if(presentinfile)
                {
                    // Debug pass
                    // std::cout << accesslevel << " vs " << Fileclearance << std::endl;
                    // Compare file access level and user access level
                    if(accesslevel == Fileclearance)
                    {
                        // Create file
                        std::ofstream appendfile(Filename + ".txt", std::ios::app);
                        appendfile << "Appending Lorem ipsum dolor sit amet" << std::endl;
                        appendfile.close();
                        std::cout << "Append successful..." << std::endl;
                        std::cout << std::endl;
                    }
                    else
                    {
                        std::cout << "Error: Cannot append to file with higher and lower access levels";
                    }
                }
                else
                {
                    std::cout << "Error: Cannot append to file that does not exist";
                }

                break;
            }
            // Read
            case 'R':{
                std::string Filename;
                std::cout << "Filename: ";
                std::cin >> Filename;

                std::ifstream chkfile("Files.store");

                // File error check sequences
                if(chkfile.eof())
                {
                    std::cerr << " End of file reached " << std::endl;
                    exit(-1);
                }
                else if(!chkfile.is_open())
                {
                    std::cerr << " Error opening file " << std::endl;
                    exit(-1);
                }
                else if(chkfile.fail())
                {
                    std::cerr << " File contains invalid data" << std::endl;
                    exit(-1);
                }
                else if(chkfile.bad())
                {
                    std::cerr << " Read and write error in program logic " << std::endl;
                    exit(-1);
                }

                std::string line;
                std::string file,user,accesslevel;
                while(getline(chkfile, line))
                {
                    if(line.find(Filename) != std::string::npos)
                    {
                        std::stringstream textstream(line);
                        getline(textstream,file,':');
                        getline(textstream,user,':');
                        getline(textstream,accesslevel,':');
                        presentinfile = true;
                        break;
                    }
                    else
                    {
                        presentinfile = false;
                    }
                }

                chkfile.close();

                // When file exists
                if(presentinfile)
                {
                    // Debug: PASS
                    // std::cout << accesslevel << " vs " << Fileclearance << std::endl;
                    int fileaccesslevel = stoi(accesslevel);
                    int useraccesslevel = stoi(Fileclearance);
                    // Compare file access level and user access level
                    if(useraccesslevel >= fileaccesslevel)
                    {
                        // Create file
                        std::ifstream rfile(Filename + ".txt");

                        // File error check sequences
                        if(rfile.eof())
                        {
                            std::cerr << " End of file reached " << std::endl;
                            exit(-1);
                        }
                        else if(!rfile.is_open())
                        {
                            std::cerr << " Error opening file " << std::endl;
                            exit(-1);
                        }
                        else if(rfile.fail())
                        {
                            std::cerr << " File contains invalid data" << std::endl;
                            exit(-1);
                        }
                        else if(rfile.bad())
                        {
                            std::cerr << " Read and write error in program logic " << std::endl;
                        }

                        std::string readline;
                        while(getline(rfile,readline))
                        {
                            std::cout << readline << std::endl;
                        }

                        std::cout << std::endl;
                        std::cout << "End of file reached..." << std::endl;

                        rfile.close();
                    }
                    else
                    {
                        std::cout << "Error: Cannot read to file with higher and lower access levels";
                    }
                }
                else
                {
                    std::cout << "Error: Cannot read file that does not exist";
                }
                break;
            }
            // Write
            case 'W':{
                std::string Filename;
                std::cout << "Filename: ";
                std::cin >> Filename;

                std::ifstream chkfile("Files.store");

                // File error check sequences
                if(chkfile.eof())
                {
                    std::cerr << " End of file reached " << std::endl;
                    exit(-1);
                }
                else if(!chkfile.is_open())
                {
                    std::cerr << " Error opening file " << std::endl;
                    exit(-1);
                }
                else if(chkfile.fail())
                {
                    std::cerr << " File contains invalid data" << std::endl;
                    exit(-1);
                }
                else if(chkfile.bad())
                {
                    std::cerr << " Read and write error in program logic " << std::endl;
                    exit(-1);
                }

                std::string line;
                std::string file,user,accesslevel;
                while(getline(chkfile, line))
                {
                    if(line.find(Filename) != std::string::npos)
                    {
                        std::stringstream textstream(line);
                        getline(textstream,file,':');
                        getline(textstream,user,':');
                        getline(textstream,accesslevel,':');
                        presentinfile = true;
                        break;
                    }
                    else
                    {
                        presentinfile = false;
                    }
                }
                chkfile.close();

                // When file exists
                if(presentinfile)
                {
                    // Debug pass
                    // std::cout << accesslevel << " vs " << Fileclearance << std::endl;
                    // Compare file access level and user access level
                    if(accesslevel == Fileclearance)
                    {
                        std::ofstream writefile(Filename + ".txt");
                        writefile << "Writing (beware of overwrites) Lorem ipsum dolor sit amet" << std::endl;
                        writefile.close();
                        std::cout << "Write successful..." << std::endl;
                        std::cout << std::endl;
                    }
                    else
                    {
                        std::cout << "Error: Cannot write to file with higher and lower access levels";
                    }
                }
                else
                {
                    std::cout << "Cannot write to file that does not exist";
                }
                break;
            }
            // List
            case 'L':{
                std::ifstream chkfile("Files.store");

                // File error check sequences
                if(chkfile.eof())
                {
                    std::cerr << " End of file reached " << std::endl;
                    exit(-1);
                }
                else if(!chkfile.is_open())
                {
                    std::cerr << " Error opening file " << std::endl;
                    exit(-1);
                }
                else if(chkfile.fail())
                {
                    std::cerr << " File contains invalid data" << std::endl;
                    exit(-1);
                }
                else if(chkfile.bad())
                {
                    std::cerr << " Read and write error in program logic " << std::endl;
                    exit(-1);
                }

                std::string line2;
                std::string FILENAME,OWNER,ACCESSLEVEL;
                std::vector<std::string> filelist;
                
                while(getline(chkfile, line2))
                {
                    std::stringstream textstream2(line2);
                    getline(textstream2,FILENAME,':');
                    getline(textstream2,OWNER,':');
                    getline(textstream2,ACCESSLEVEL,':');
                    filelist.push_back(FILENAME);
                }
                chkfile.close();
    
                std::cout << std::endl;
                for (std::string file : filelist)
                {
                    std::cout << file << std::endl;
                }
                break;
            }
            // Save
            case 'S':{
                std::ifstream chkfile("Files.store");

                if(chkfile.is_open())
                {
                    chkfile.close();
                }
                // >_<
                break;
            }
            // Exit
            case 'E':{
                char yesno;
                std::cout << "Shut down the FileSystem? (Y)es or (N)o: ";
                std::cin >> yesno;

                if(yesno == 'Y')
                {
                   exited = true;
                }

                break;
            }    
        }
    }
}