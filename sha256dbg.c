/*****************************************************************************
sha256dbg -- Copyright (c) 2013 Martin Maurer

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
******************************************************************************/

#include <stdio.h>

int clausecounter = 0;

int main(int argc, char *argv[])
{
  int var;
  int rv;
  int clausenumber;
  int i;
  unsigned long w[64];
  unsigned long h_out[8];
  unsigned long k[64];
  unsigned long tmpa[5];
  unsigned long tmpb[3];
  unsigned long ABCDEFGH[8];
  unsigned long tmp6ABCDEFGH[14*(1+64)];
  int pos;

  static const unsigned long w_org[64] = {
    0x68656C6C, 0x6F800000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000028, 0x7594884C, 0x6F910000, 0xD532D15A, 0xA01BDE7A,
    0x32B37C8B, 0x94DA02F9, 0xD1D853F8, 0xB69B56C2, 0x934804C3,
    0x96C77CA5, 0xA2F94846, 0x849744EF, 0x21DD3E6A, 0x1CA36B00,
    0x3F957A61, 0x2079CF86, 0x6BFC7C3B, 0x0C209D4B, 0x2228225C,
    0xEE1AD25B, 0xC5D09850, 0x07331882, 0x977423C5, 0xA667D6F9,
    0xBC044B46, 0x95859031, 0x5C98CA62, 0x64860C1B, 0x7EE7C777,
    0x16C55872, 0x7CF67D29, 0x4857C138, 0xA37F4A81, 0x35F8FD03,
    0xF16FFCE2, 0x6D549F9C, 0xA12FF314, 0xF1818DB4, 0xF9CAD136,
    0xC960D70C, 0x3A18F5F8, 0xF5FDF2BA, 0xE79A1B2A, 0x5DEA4345,
    0x701CC2F2, 0x3C9B25E2, 0xC9670B22, 0x3E3CB561
  };

  static const unsigned long hash_org[64] = {
    0x2CF24DBA, 0x5FB0A30E, 0x26E83B2A, 0xC5B9E29E, 0x1B161E5C,
    0x1FA7425E, 0x73043362, 0x938B9824
  };

  static const unsigned long k_org[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };

  static const unsigned long A0_org[64] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
    0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  };

  memset(w,     0x00, sizeof(w));
  memset(h_out, 0x00, sizeof(h_out));
  memset(k,     0x00, sizeof(k));
  memset(tmpa,   0x00, sizeof(tmpa));
  memset(tmpb,   0x00, sizeof(tmpb));
  memset(ABCDEFGH,   0x00, sizeof(ABCDEFGH));
  memset(tmp6ABCDEFGH,   0x00, sizeof(tmp6ABCDEFGH));

  if(argc != 1)
    {
    printf("type resfile | sha256dbg\n");
    exit(1);
    }

  if(fscanf(stdin, "SAT\n") != 0)
  {
    fprintf(stderr, "error: expected: SAT\n");
    exit(1);
  }

  while(1)
  {
    while(1)
    {
      rv = fscanf(stdin, "%d", &var);
      if(rv == -1)
      {
        break;
      }
      else if(rv != 1)
      {
        fprintf(stderr, "error: var=%d rv=%d\n", var, rv);
        exit(1);
      }

      if(var == 0) break;

      // printf("%d 0\n", var);

      if(var < 0);
      else if(var >= 1 && var < 1 + 64 * 32)
      {
        // printf("%d 0\n", var);
        w[(var-1) / 32] |= (1 << ((var-1) % 32));
      }
      else if(var >= 2049 && var < 2049 + 8 * 32)
      {
        // printf("%d 0\n", var);
        h_out[(var-2049) / 32] |= (1 << ((var-2049) % 32));
      }
      else if(var >= 26306 && var < 26306 + 64 * 32)
      {
        // printf("%d 0\n", var);
        k[(var-26306) / 32] |= (1 << ((var-26306) % 32));
      }
      else if(var >= 2305 && var < 2305 + 5 * 32)
      {
        // printf("%d 0\n", var);
        tmpa[(var-2305) / 32] |= (1 << ((var-2305) % 32));
      }
      else if(var >= 2466 && var < 2466 + 3 * 32)
      {
        // printf("%d 0\n", var);
        tmpb[(var-2466) / 32] |= (1 << ((var-2466) % 32));
      }
      else if(var >= 28354 && var < 28354 + 8 * 32)
      {
        // printf("%d 0\n", var);
        ABCDEFGH[(var-28354) / 32] |= (1 << ((var-28354) % 32));
      }
      else if(var >= 28610 && var < 28610 + 14 * 32 * 64)
      {
        // printf("%d 0\n", var);
        tmp6ABCDEFGH[14 + (var-28610) / 32] |= (1 << ((var-28610) % 32));
      }
    }

    if(rv == -1)
    {
      break;
    }
  }

  for(i = 0; i < 64; i++)
  {
    printf("w[%2u]=0x%08X -> ", i, w[i]);
    if(w[i] == w_org[i]) printf("OK\n");
    else                 printf("ERROR (%08X <-> %08X)\n", w[i], w_org[i]);
  }
  for(i = 0; i < 8; i++)
  {
    printf("h_out[%u]=0x%08X -> ", i, h_out[i]);
    if(h_out[i] == hash_org[i]) printf("OK\n");
    else                        printf("ERROR (%08X <-> %08X)\n", h_out[i], hash_org[i]);
  }
  for(i = 0; i < 64; i++)
  {
    printf("k[%2u]=0x%08X -> ", i, k[i]);
    if(k[i] == k_org[i]) printf("OK\n");
    else                 printf("ERROR (%08X <-> %08X)\n", k[i], k_org[i]);
  }
  for(i = 0; i < 8; i++)
  {
    printf("%c[0]=0x%08X -> ", 'A' + i, ABCDEFGH[i]);
    if(ABCDEFGH[i] == A0_org[i]) printf("OK\n");
    else                         printf("ERROR (%08X <-> %08X)\n", ABCDEFGH[i], A0_org[i]);
  }

  pos = 14;
  for(i = 1; i <= 64; i++)
  {
    printf("tmp1 [%2u]=0x%08X\n", i, tmp6ABCDEFGH[pos++]);
    printf("tmp1a[%2u]=0x%08X\n", i, tmp6ABCDEFGH[pos++]);
    printf("tmp1b[%2u]=0x%08X\n", i, tmp6ABCDEFGH[pos++]);
    printf("tmp2 [%2u]=0x%08X\n", i, tmp6ABCDEFGH[pos++]);
    printf("tmp2a[%2u]=0x%08X\n", i, tmp6ABCDEFGH[pos++]);
    printf("tmp2b[%2u]=0x%08X\n", i, tmp6ABCDEFGH[pos++]);
    printf("A    [%2u]=0x%08X\n", i, tmp6ABCDEFGH[pos++]);
    printf("B    [%2u]=0x%08X\n", i, tmp6ABCDEFGH[pos++]);
    printf("C    [%2u]=0x%08X\n", i, tmp6ABCDEFGH[pos++]);
    printf("D    [%2u]=0x%08X\n", i, tmp6ABCDEFGH[pos++]);
    printf("E    [%2u]=0x%08X\n", i, tmp6ABCDEFGH[pos++]);
    printf("F    [%2u]=0x%08X\n", i, tmp6ABCDEFGH[pos++]);
    printf("G    [%2u]=0x%08X\n", i, tmp6ABCDEFGH[pos++]);
    printf("H    [%2u]=0x%08X\n", i, tmp6ABCDEFGH[pos++]);
  }
}


