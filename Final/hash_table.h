// Code written by: Lukáš Kulda (xkulda01@stud.fit.vutbr.cz)
// ISA Project - DNS export by syslog protocol
// 8.10.2018
// Hash table - tento kód je převzatý z vlastní implementace projektu do předmětu IAL 2017
// kód je upravený tak, aby byl použitelný pro potřeby projektu ISA 2018 - varianta 2. DNS export


/* Hlavičkový soubor pro c016.h - Tabulka s Rozptýlenými Položkami,
**  obsahuje jednak nutné includes a externované proměnné,
**  ale rovnež definici datových typů. Tento soubor neupravujte!
**  Téma:  Tabulka s explicitně zřetězenými synonymy
**                      První implementace: Petr Přikryl, prosinec 1994
**                      Do jazyka C prepsal a upravil: Vaclav Topinka, 2005
**                      Úpravy: Karel Masařík, říjen 2013
**                      Úpravy: Radek Hranický, říjen 2014
**                      Úpravy: Radek Hranický, listopad 2015
**                      Úpravy: Radek Hranický, říjen 2016
**
***/

#ifndef ISA_HASH_TABLE_H
#define ISA_HASH_TABLE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// Maximum size of hash table
#define MAX_HTSIZE 101

/* typ klíče (například identifikace zboží) */
typedef char* tKey;

/* typ obsahu (například cena zboží) */
typedef int tData;

/*Datová položka TRP s explicitně řetězenými synonymy*/
typedef struct tHTItem{
	tKey key;				/* klíč  */
	tData data;				/* obsah */
	struct tHTItem* ptrnext;	/* ukazatel na další synonymum */
} tHTItem;

/* TRP s explicitně zřetězenými synonymy. */
typedef tHTItem* tHTable[MAX_HTSIZE];

/* Pro účely testování je vhodné mít možnost volby velikosti pole,
   kterým je vyhledávací tabulka implementována. Fyzicky je deklarováno
   pole o rozměru MAX_HTSIZE, ale při implementaci vašich procedur uvažujte
   velikost HTSIZE.  Ve skriptu se před voláním řešených procedur musí
   objevit příkaz HTSIZE N, kde N je velikost požadovaného prostoru.

   POZOR! Pro správnou funkci TRP musí být hodnota této proměnné prvočíslem.
*/

/* Hlavičky řešených procedur a funkcí. */

/*          -------
** Rozptylovací funkce - jejím úkolem je zpracovat zadaný klíč a přidělit
** mu index v rozmezí 0..HTSize-1.  V ideálním případě by mělo dojít
** k rovnoměrnému rozptýlení těchto klíčů po celé tabulce.  V rámci
** pokusů se můžete zamyslet nad kvalitou této funkce.  (Funkce nebyla
** volena s ohledem na maximální kvalitu výsledku). }
*/
int hashCode(tKey key);

/*
** Inicializace tabulky s explicitně zřetězenými synonymy.  Tato procedura
** se volá pouze před prvním použitím tabulky.
*/
void htInit(tHTable* ptrht);

/* TRP s explicitně zřetězenými synonymy.
** Vyhledání prvku v TRP ptrht podle zadaného klíče key.  Pokud je
** daný prvek nalezen, vrací se ukazatel na daný prvek. Pokud prvek nalezen není,
** vrací se hodnota NULL.
**
*/
tHTItem* htSearch(tHTable* ptrht, tKey key);

/*
** TRP s explicitně zřetězenými synonymy.
** Tato procedura vkládá do tabulky ptrht položku s klíčem key a s daty
** data.  Protože jde o vyhledávací tabulku, nemůže být prvek se stejným
** klíčem uložen v tabulce více než jedenkrát.  Pokud se vkládá prvek,
** jehož klíč se již v tabulce nachází, aktualizujte jeho datovou část.
**
** Využijte dříve vytvořenou funkci htSearch.  Při vkládání nového
** prvku do seznamu synonym použijte co nejefektivnější způsob,
** tedy proveďte.vložení prvku na začátek seznamu.
**/
void htInsert(tHTable* ptrht, tKey key, tData data);

/*
** TRP s explicitně zřetězenými synonymy.
** Tato funkce zjišťuje hodnotu datové části položky zadané klíčem.
** Pokud je položka nalezena, vrací funkce ukazatel na položku
** Pokud položka nalezena nebyla, vrací se funkční hodnota NULL
**
** Využijte dříve vytvořenou funkci HTSearch.
*/
tData* htRead(tHTable* ptrht, tKey key);

/*
** TRP s explicitně zřetězenými synonymy.
** Tato procedura vyjme položku s klíčem key z tabulky
** ptrht.  Uvolněnou položku korektně zrušte.  Pokud položka s uvedeným
** klíčem neexistuje, dělejte, jako kdyby se nic nestalo (tj. nedělejte
** nic).
**
** V tomto případě NEVYUŽÍVEJTE dříve vytvořenou funkci HTSearch.
*/
void htDelete(tHTable* ptrht, tKey key);

/* TRP s explicitně zřetězenými synonymy.
** Tato procedura zruší všechny položky tabulky, korektně uvolní prostor,
** který tyto položky zabíraly, a uvede tabulku do počátečního stavu.
*/
void htClearAll(tHTable* ptrht);

/*
 * Procedure that inserts or updates resource record.
 */
void ht_process_rr(tHTable* ptrht, char* rr_string);

/*
 * Procedure that prints whole content of hash table.
 */
void ht_foreach(tHTable* ptrht, void (*item_callback)(tHTItem* item));

/*
 * Procedure that prints given item of hash table.
 */
void ht_print_item(tHTItem* item);

#endif //ISA_HASH_TABLE_H
