/********************************************************************
** This header file declares the classes, structs, and function 
** declarations used in wallHack.cpp.
********************************************************************/

#include <Windows.h>
#include <iostream>
#include <vector>

#ifndef WALLHACK_H
#define WALLHACK_H

//Forward declaring. Defined below.
class ent;

//Vec3 will be used to hold the entity's position and head position, and also the
//NDC (normalized device coordinates) in the WorldToScreen function.
struct Vec3
{
	float x, y, z;
};

//Only one Vec4 will be used, and it will hold the clip coordinates used in the WorldToScreen function.
struct Vec4
{
	float x, y, z, w;
};

//Vec2 will be used to hold screen position of the entity's body and head after
//the WorldToScreen functions transforms 3D coordinates to a screen position.
struct Vec2
{
	float x, y;
};

//Array that holds up to 31 (max of 32 players in a match minus the local player) ent pointers.
struct entList
{
	ent* ents[31];
};

//currentMatch class holds some useful addresses and helper functions for the current match that the local player is in.
class currentMatch
{
	public:
        //Stores the window size of the AssaultCube client in variables. Used these variables since the WorldToScreen function
        //requires the window size to be passed to it for accuracy. Without reading the window size from AssaultCube's memory,
        //the size would have to be a fixed value (i.e. passing 1024 and 768, or 1920 and 1080) which is inconvenient for testing.
        int windowSizeH = *(int*)(0x510C94);
        int windowSizeV = *(int*)(0x510C98);

		//Each gamemode has a unique number. This will be used to determine if it is a team-based or free-for-all gamemode (converted to an int).
		int gameMode = *(int*)(0x50F49C);
		
		//Holds the number of players in a given match (converted to an int).
		int amountOfPlayers = *(int*)(0x50f500);

		//Holds the start of the game's view matrix (float since it deals with coordinates).
		float* viewMatrix = (float*)(0x501AE8);

		//Converts the local player address to a type ent (defined below) so that we can access the localPlayer's team number.
		ent* localPlayer = *(ent**)0x50F4F4;

		//entList holds the start of the entity list (as an ent object).
		entList* entities = *(entList**)0x50F4F8;

		//Simple helper function to determine if an entity is an enemy player.
		bool isEnemyPlayer(ent* entity);

		//Simple helper function to determine if a match is team-based or free-for-all.
		bool isTeamBased();

		//Simple helper function to determine if an entity is alive or dead.
		bool isAlive(ent* entity);
};

//Generated by ReClass.NET (borrowed from teammates). The only things I decided to use from this was
//the ent's team and state. I used each of these in simple helper functions to determine if an entity
//is on the local player's team and to check if it is alive/dead.
class ent
{
	public:
		char pad_0000[4]; //0x0000	
		Vec3 headPos; //0x0004
		char pad_0010[36]; //0x0010
		Vec3 bodyPos; //0x0034
		Vec3 yawPitchRoll; //0x0040
		char pad_004C[172]; //0x004C
		int32_t playerHealth; //0x00F8
		int32_t playerArmor; //0x00FC
		char pad_0100[556]; //0x0100

		//Holds the team value of the entity. Used for comparison to determine
		//if an entity is an enemy of the local player.
		int32_t team; //0x032C

		char pad_0330[8];

		//Holds the alive/dead status of the entity. Used for comparison to determine
		//if an entity is alive or dead. 0 == alive, 1 == dead.
		int32_t state;	//0x0338

		char pad_033C[1832];
};

//Helper functions for drawing the rectangle around entities and converting 3D coordinates to screen position.
void drawFilledRectangle(float x, float y, float w, float h, HBRUSH brush, HDC deviceContext);
void drawBorderBox(float x, float y, float w, float h, float thickness, HBRUSH brush, HDC deviceContext);
bool WorldToScreen(Vec3 pos, Vec2 &screen, float matrix[16], int windowWidth, int windowHeight);

//Function that contains most of the legwork of the hack and will be injected.
DWORD WINAPI wallHackMain();

#endif