# Responsible Disclosure
import pygame as pg
import sys

pg.init()

# --- Constants ---
WIDTH, HEIGHT = 900, 600
screen = pg.display.set_mode((WIDTH, HEIGHT))
pg.display.set_caption("Responsible Disclosure")

font = pg.font.SysFont("Consolas", 18)

bugs = 100_000_000_000
target_score = 100_000_000

enc = [108, 102, 111, 103, 113, 81, 38, 109, 117, 46,
       104, 43, 125, 86, 117, 110, 94, 103, 155, 152, 89,
       107, 125, 168, 105, 110, 117, 95, 64, 106, 126, 181]

def decrypt_flag(token):
    return ''.join([chr((val ^ (token + i)) - i) for i, val in enumerate(enc)])

def show_victory():
    tokentemp = 100_000_000
    while tokentemp >= (target_score + 2**20):
        tokentemp -= 2**20
    token = tokentemp // 10**7
    flag = decrypt_flag(token)
    print("Flag:", flag) 
    screen.fill((0, 0, 0))
    screen.blit(font.render("Elite Bug Hunter!", True, (0, 255, 0)), (180, 200))
    screen.blit(font.render(f"Flag: {flag}", True, (255, 255, 0)), (100, 250))
    pg.display.flip()
    pg.time.wait(10000)
    pg.quit()
    sys.exit()


show_victory()
