#ifndef _LISTFUNC_H
#define _LISTFUNC_H

void addElement(struct in_addr ip, time_t tm);
struct occAddr* findElement(struct in_addr ip);
int updateElement(struct in_addr ip, time_t tm);
int removeElement(struct in_addr ip);
void clearElements();
size_t countElements();

#endif
