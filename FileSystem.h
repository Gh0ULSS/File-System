/*
Student Author: Min Htut Myat
Student Number: 7058949
Subject: CSCI262 Systems Security

Assignment 1 Part Two
*/
#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#include <string>

// Required variables and function prototypes
extern std::string inputusername;
extern std::string Fileclearance;
extern bool presentinfile;

void Initialize();
void Login_Authentication();
void Filesystem();
void FileSystemMenu();

#endif 