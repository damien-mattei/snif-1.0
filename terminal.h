/*****************************************************************************
 *
 * S.N.I.F : Sniff Network Interface's Frames
 *
 * Copyright (C) 2006  Damien MATTEI <Damien.MATTEI@orange.fr>

 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 ****************************************************************************/

/* Terminal definitions used to set color of chars, bright and more */

#define RESET		0
#define BRIGHT 		1
#define DIM		2
#define UNDERLINE 	3
#define BLINK		4
#define REVERSE		7
#define HIDDEN		8

#define BLACK 		0
#define RED		1
#define GREEN		2
#define YELLOW		3
#define BLUE		4
#define MAGENTA		5
#define CYAN		6
#define	WHITE		7

/* come back in normal mode - reset attributes and color */
#define NORMALMODE()  printf("%c[0m", 0x1B)

/* set attribute and color */
#define SETATTCOL( a , c ) printf("%c[%d;%dm", 0x1B, a, c + 30 )

#define SETATTRIB( a ) printf("%c[%dm", 0x1B, a )

#define SETCOLOR( c ) printf("%c[%dm", 0x1B,  c + 30 )


/* Changes terminal color n ('0' through 'f') to the color
 * represented by the RGB values rr, gg, and bb.
 * (Compatible with Linux console.)
 */
#define SETRGB( n , r , g , b ) printf("%c]P%X%02X%02X%02X", 0x1B, n ,r , g , b )
