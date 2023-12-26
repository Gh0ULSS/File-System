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

int main(int argc, char *argv[])
{

    std::cout << "===============================================" << std::endl;
    std::cout << "====== WELCOME TO SECURE AUTHENTICATION =======" << std::endl;
    std::cout << "====== AND ACCESS CONTROLLED FILE SYSTEM ======" << std::endl;
    std::cout << "================================= ~ Gh0u1SS ===" << std::endl;
    std::cout << std::endl;

    // No command line parameters are specified
    if(argc == 1) // Handle for running program without command line arguments
    {
       std::cout << "Login and Authentication to file system" << std::endl;

       // MD5 test
       std::string teststr = "This is a test";
       std::cout << "MD5 (\"" << teststr << "\") = " << md5(teststr) << std::endl;

       Login_Authentication();
    }
    else
    {
        // command line parameter -i for initialization 
        std::string initarg = argv[1];
        if(initarg == "-i")
        {
            // MD5 test
            std::string teststr = "This is a test";
            std::cout << "MD5 (\"" << teststr << "\") = " << md5(teststr) << std::endl;

            std::cout << "Initialization executing... " << std::endl;
            Initialize();
        }
    }
    return 0;
}