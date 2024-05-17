#ifndef _LOG_H
#define _LOG_H

#define logs(fmt, ... ) \
{ \
    char ____str[512]; \
    sprintf(____str, "%s >> %s %d\n", fmt, __FILE__, __LINE__ ); \
    printk(____str, ##__VA_ARGS__); \
}

#endif
