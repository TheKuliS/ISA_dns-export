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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash_table.h"
int HTSIZE = MAX_HTSIZE;

/*          -------
** Rozptylovací funkce - jejím úkolem je zpracovat zadaný klíč a přidělit
** mu index v rozmezí 0..HTSize-1.  V ideálním případě by mělo dojít
** k rovnoměrnému rozptýlení těchto klíčů po celé tabulce.  V rámci
** pokusů se můžete zamyslet nad kvalitou této funkce.  (Funkce nebyla
** volena s ohledem na maximální kvalitu výsledku). }
*/

int hashCode ( tKey key ) {
	int retval = 1;
	int keylen = strlen(key);
	for ( int i=0; i<keylen; i++ )
	{
		retval += key[i];
	}

	return ( retval % HTSIZE );
}

/*
** Inicializace tabulky s explicitně zřetězenými synonymy.  Tato procedura
** se volá pouze před prvním použitím tabulky.
*/
void htInit ( tHTable* ptrht ) {

	for (int i = 0; i < HTSIZE; i++) {
		(*ptrht)[i] = NULL;
	}
}

/* TRP s explicitně zřetězenými synonymy.
** Vyhledání prvku v TRP ptrht podle zadaného klíče key.  Pokud je
** daný prvek nalezen, vrací se ukazatel na daný prvek. Pokud prvek nalezen není,
** vrací se hodnota NULL.
**
*/
tHTItem* htSearch ( tHTable* ptrht, tKey key ) {
	if (*ptrht == NULL || (*ptrht)[hashCode(key)] == NULL) { // Pokud nebyla tabulka inicialzována, nebo pokud hledaný prvek v tabulce není.
		return NULL;
	}
	else {
		tHTItem *hledany = (*ptrht)[hashCode(key)]; // Pomocná proměnná pro hledaný prvek.while (hledany != NULL) { // Dokud máme co hledat
			if (strcmp(hledany->key, key) == 0) { // Pokud se shodují
				return hledany; // Vracím ukazatel na daný prvek.
			}
			else {
				hledany = hledany->ptrnext; // Jinak pokračuji dál v seznamu.
			}
		}
	return NULL; // Pokud jsme nic nenalezli
}

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
void htInsert ( tHTable* ptrht, tKey key, tData data ) {
	if (*ptrht != NULL) {
		tHTItem *vyhledany = htSearch(ptrht, key); // Vyhledání prvku.
		unsigned int index = hashCode(key); // Index klíče

		if (vyhledany == NULL) { // Prvek ještě neexistuje.
			if ((*ptrht)[index] == NULL) { // Je prázdný.
				(*ptrht)[index] = malloc(sizeof(struct tHTItem));
				(*ptrht)[index]->key = key;
				(*ptrht)[index]->data = data;
				(*ptrht)[index]->ptrnext = NULL;
			}
			else { // Je zde nějaké synonymum.
				vyhledany = malloc(sizeof(struct tHTItem));
				vyhledany->key = key;
				vyhledany->data = data;
				vyhledany->ptrnext = (*ptrht)[index];
				(*ptrht)[index] = vyhledany;
			}
		}
		else { // Prvek již existuje.
			if (strcmp(vyhledany->key, key) == 0) { // Pokud se shodují
				vyhledany->data = data; // Přepíšeme data.
			}
		}
	}
}

/*
** TRP s explicitně zřetězenými synonymy.
** Tato funkce zjišťuje hodnotu datové části položky zadané klíčem.
** Pokud je položka nalezena, vrací funkce ukazatel na položku
** Pokud položka nalezena nebyla, vrací se funkční hodnota NULL
**
** Využijte dříve vytvořenou funkci HTSearch.
*/
tData* htRead ( tHTable* ptrht, tKey key ) {

	if (*ptrht == NULL || (*ptrht)[hashCode(key)] == NULL) { // Pokud nebyla tabulka inicialzována, nebo pokud hledaný prvek v tabulce není.
		return NULL;
	}
	else {
		tHTItem *hledany = htSearch(ptrht, key);

		if (hledany != NULL) {
			return (&hledany->data); // Vracíme ukazatel na položku.
		}
	}
	return NULL;
}

/*
** TRP s explicitně zřetězenými synonymy.
** Tato procedura vyjme položku s klíčem key z tabulky
** ptrht.  Uvolněnou položku korektně zrušte.  Pokud položka s uvedeným
** klíčem neexistuje, dělejte, jako kdyby se nic nestalo (tj. nedělejte
** nic).
**
** V tomto případě NEVYUŽÍVEJTE dříve vytvořenou funkci HTSearch.
*/
void htDelete ( tHTable* ptrht, tKey key ) {

	if ((*ptrht)[hashCode(key)] != NULL) { // Pokud položka s uvedeným klíčem existuje.
		tHTItem *mazany = (*ptrht)[hashCode(key)];
		tHTItem *predchozi = NULL;

		while (mazany != NULL) { // Dokud máme co procházet.
			if (strcmp(mazany->key, key) == 0) { // Pokud se shodují
				if (predchozi != NULL) { // Pokud jsme se ještě nedostali na konec.
					predchozi->ptrnext = mazany->ptrnext;
				}
				if (mazany == (*ptrht)[hashCode(key)]) { // Pokud mazaný je první, tak následující musím nastavit na první (převázat seznam).
					(*ptrht)[hashCode(key)] = mazany->ptrnext;
				}
				free(mazany); // Nakonec mazaný prvek uvolníme.
				mazany = NULL;
				break;
			}
			else { // Pokud jsme ještě prvek s daným klíčem nenašli, tak jdeme na další.
				predchozi = mazany;
				mazany = mazany->ptrnext;
			}
		}
	}
}

/* TRP s explicitně zřetězenými synonymy.
** Tato procedura zruší všechny položky tabulky, korektně uvolní prostor,
** který tyto položky zabíraly, a uvede tabulku do počátečního stavu.
*/
void htClearAll ( tHTable* ptrht ) {

	tHTItem *ruseny = NULL;
	for (int i = 0; i < HTSIZE; i++) {
		while ((*ptrht)[i] != NULL) { // Dokud máme co zrušit.
			ruseny = (*ptrht)[i];
			if(ruseny->ptrnext != NULL) { // Pokud nejsme na posledním.
				(*ptrht)[i]=(*ptrht)[i]->ptrnext; // Ukážeme na další co chceme zrušit.
				free(ruseny); // Zrušíme.
				ruseny = NULL;
			}
			else { // Jinak jsme na konci.
				break;
			}
		} // Pak už jen uvedeme do původního stavu.
		(*ptrht)[i] = NULL;
	}
}

/*
 * Procedure that inserts or updates resource record.
 */
void ht_process_rr(tHTable* ptrht, char* rr_string)
{
	tHTItem* rr_item;

	rr_item = htSearch(ptrht, rr_string);

	if (rr_item == NULL)
	{
		htInsert(ptrht, rr_string, 1);
	}
	else
	{
		rr_item->data = rr_item->data + 1;
		free(rr_string);
	}

}

/*
 * Procedure that prints whole content of hash table.
 */
void ht_foreach(tHTable* ptrht, void (*item_callback)(tHTItem* item))
{
	for(int i = 0; i < HTSIZE; i++)
	{
		tHTItem* processed_item = (*ptrht)[i];
		while (processed_item != NULL)
		{
			item_callback(processed_item);
			processed_item = processed_item->ptrnext;
		}
	}
}

/*
 * Procedure that prints given item of hash table.
 */
void ht_print_item(tHTItem* item)
{
	fprintf(stdout, "%s %d\n", item->key, item->data);
}