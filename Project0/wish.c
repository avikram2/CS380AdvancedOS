#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/wait.h>
#include <fcntl.h>

#define STR_SIZE 1024

#define MAX_CMD_TOKENS 40

#define PTR_FREE(ptr) \
    if (ptr != NULL)  \
    {                 \
        free(ptr);    \
        ptr = NULL;   \
    }

#define ARR_FREE(arr, size)           \
    for (size_t i = 0; i < size; ++i) \
    {                                 \
        PTR_FREE(arr[i]);              \
    }

static const char error_message[30] = "An error has occurred\n";

#define PRINT_ERROR write(STDERR_FILENO, error_message, strlen(error_message));

char *pathArr[STR_SIZE];
size_t pathSize = 0;

void clearPath()
{
    extern size_t pathSize;
    extern char *pathArr[];
    for (size_t i = 0; i < pathSize; ++i)
    {
        if (pathArr[i])
        {
            free(pathArr[i]);
        }
    }
    pathSize = 0;
}

void addToPath(char *pathVar)
{
    extern char *pathArr[];
    extern size_t pathSize;
    char *c = (char *)malloc(strlen(pathVar) + 1);
    strcpy(c, pathVar);
    pathArr[pathSize] = c;
    ++pathSize;
}

void initPath()
{
    extern size_t pathSize;
    pathSize = 0;
    addToPath("/bin");
}

void printPath()
{
    extern size_t pathSize;
    extern char *pathArr[];
    for (size_t i = 0; i < pathSize; ++i)
    {
        printf("Path member: %s\n", pathArr[i]);
    }
}

void getFilepath(const char *filename, char **out)
{
    extern size_t pathSize;
    extern char *pathArr[];
    char localCopy[STR_SIZE];

    // printf("filename: %s\n", filename);

    if (pathSize == 0)
    {
        if (0 == access(filename, X_OK))
        {
            strcpy((*out), filename);
            return;
        }

        *out = NULL;
        return;
    }

    for (size_t i = 0; i < pathSize; ++i)
    {
        strcpy(localCopy, pathArr[i]);
        strcat(localCopy, "/");
        strcat(localCopy, filename);
        if (0 == access(localCopy, X_OK))
        {
            // exists
            strcpy((*out), localCopy);
            return;
        }
    }
    *out = NULL;
    return;
}

char *strtrim(char *token)
{
    if (token == NULL)
        return NULL;

    if (strlen(token) == 0)
    {
        return NULL;
    }

    // printf("token: %s\n", token);

    size_t start = 0;
    size_t end = strlen(token) - 1;

    while (end > start && isspace((unsigned char)(token[end])) != 0)
    {
        --end;
    }

    while ((start < strlen(token)) && isspace((unsigned char)(token[start])) != 0)
    {
        ++start;
    }

    if (end <= start)
    {
        return NULL;
    }

    char *retPtr = (void *)malloc(end - start + 2);
    memmove(retPtr, token + start, end - start + 1);
    retPtr[end - start + 1] = '\0';
    return retPtr;
}

void checkForRedirection(char *command, char *fileName, int *flag, int *valid)
{
    char *origString = malloc(strlen(command) + 1);
    strcpy(origString, command);
    char *origPtr = origString;
    const char delim[] = ">";
    char *token, *token2, *token3;
    token = strsep(&origString, delim);
    *flag = 1;
    *valid = 1;

    if (token == NULL || (strlen(token) == 0))
    {
        *flag = 1;
        *valid = 0;
        PTR_FREE(origPtr);
        return;
    }

    if (origString == NULL)
    {
        *flag = 0;
        *valid = 0;
        PTR_FREE(origPtr);
        return;
    }

    if (strcmp(token, origString) == 0)
    {
        *flag = 0;
        *valid = 0;
        PTR_FREE(origPtr);
        return;
    }
    token2 = strtrim(strsep(&origString, delim));
    token3 = strtrim(strsep(&origString, delim));

    if (token2 == NULL || strlen(token2) == 0)
    {
        *flag = 1;
        *valid = 0;
        PTR_FREE(origPtr);
        PTR_FREE(token2);
        PTR_FREE(token3);
        return;
    }

    if (token3 != NULL && strlen(token3) > 0)
    {
        *flag = 1;
        *valid = 0;
        PTR_FREE(origPtr);
        PTR_FREE(token2);
        PTR_FREE(token3);
        return;
    }

    char *token2copy = token2;
    char *token2orig = token2;

    token2 = strsep(&token2copy, " ");

    // printf("token2: %s\n", token2);
    // printf("token2cpy: %s\n", token2copy);

    if (token2copy != NULL)
    {
        if (strcmp(token2copy, "") != 0)
        {
            *flag = 1;
            *valid = 0;
            PTR_FREE(origPtr);
            PTR_FREE(token2orig);
            PTR_FREE(token3);
            return;
        }
    }

    // if (0 != access(token2, F_OK))
    // {
    //     *flag = 1;
    //     *valid = 0;
    //     PTR_FREE(origPtr);
    //     PTR_FREE(token2orig);
    //     PTR_FREE(token3);
    //     return;
    // }

    strcpy(fileName, token2);
    strcpy(command, token);
    PTR_FREE(origPtr);
    PTR_FREE(token2orig);
    PTR_FREE(token3);
}

void parseExecuteCommand(char *newLine)
{
    const char error_message[30] = "An error has occurred\n";
    char *command[STR_SIZE];
    unsigned int instance = 0;
    char *token = NULL;
    char *token2 = NULL;
    char *token3 = NULL;
    char *origPtr2 = NULL;
    char *origPtr2Orig = NULL;
    char *origPtr = newLine;
    const char delim1[] = "&";
    // printf("origPtr: %s\n", origPtr);
    token = strsep(&origPtr, delim1);
    while (token != NULL)
    {
        if (strlen(token) > 0)
        {
            char *trimTok = strtrim(token);
            if (trimTok != NULL)
            {
                // printf("trimTok %s\n", trimTok);
                command[instance] = trimTok;
                ++instance;
            }
        }
        token = strsep(&origPtr, delim1);
    }
    unsigned int i = 0;
    const char delim[] = " ";
    unsigned int internalCounter = 0;

    char *currCommand[instance][MAX_CMD_TOKENS];
    unsigned int cmdArgs[instance];
    unsigned int redirectionFlags[instance];
    unsigned int redirectionValids[instance];
    char redirectionFilenames[instance][STR_SIZE];

    for (i = 0; i < instance; ++i)
    {
        internalCounter = 0;
        origPtr2 = (void *)malloc(sizeof(char) * STR_SIZE);
        origPtr2Orig = origPtr2;
        char redirectionFilename[STR_SIZE];
        int redirectionFlag = 0;
        int redirectionValid = 0;
        checkForRedirection(command[i], redirectionFilename, &redirectionFlag, &redirectionValid);
        // printf("command: %s\n", command[i]);

        redirectionFlags[i] = redirectionFlag;
        redirectionValids[i] = redirectionValid;
        strcpy(redirectionFilenames[i], redirectionFilename);
        // printPath();
        // printf("RedF: %s\n", redirectionFilename);
        strcpy(origPtr2, command[i]);
        token = strsep(&origPtr2, delim);
        while (token != NULL)
        {
            if (strlen(token) > 0)
            {
                if (token[strlen(token) - 1] == '\n')
                {
                    token[strlen(token) - 1] = '\0';
                }
            }
            if (strcmp(token, "exit") == 0)
            {
                token2 = strsep(&origPtr2, delim);
                if ((token2 != NULL) && strlen(token2) > 0)
                {
                    write(STDERR_FILENO, error_message, strlen(error_message));
                    break;
                }
                if (newLine)
                    free(newLine);
                clearPath();
                exit(0);
            }
            else if (strcmp(token, "cd") == 0)
            {
                token2 = strsep(&origPtr2, delim);
                if ((token2 == NULL) || strlen(token2) == 0)
                {
                    write(STDERR_FILENO, error_message, strlen(error_message));
                    break;
                }
                token3 = strsep(&origPtr2, delim);
                if (token3 != NULL)
                {
                    if (strlen(token3) > 0)
                    {
                        write(STDERR_FILENO, error_message, strlen(error_message));
                        break;
                    }
                }
                int chdirRet = chdir(token2);
                if (chdirRet == -1)
                {
                    write(STDERR_FILENO, error_message, strlen(error_message));
                    break;
                }
            }
            else if (strcmp(token, "path") == 0)
            {
                token2 = strsep(&origPtr2, delim);
                if ((token2 == NULL) || strlen(token2) == 0)
                {
                    // reset Path
                    clearPath();
                    break;
                }
                else
                {
                    while (token2 != NULL && strlen(token2) > 0)
                    {
                        addToPath(token2);
                        token2 = strsep(&origPtr2, delim);
                    }
                    break;
                }
            }
            else
            {
                if (strlen(token) > 0)
                {
                    char *currCom = (void *)malloc(STR_SIZE * sizeof(char));
                    strcpy(currCom, token);
                    currCommand[i][internalCounter] = currCom;
                    ++internalCounter;
                }
            }

            token = strsep(&origPtr2, delim);
            token2 = NULL;
            token3 = NULL;
        }

        currCommand[i][internalCounter] = NULL;
        cmdArgs[i] = internalCounter;
    }

    for (unsigned int i = 0; i < instance; ++i)
    {
        // printf("cmdArgs: %u\n", internalCounter);
        // printf("CurrCom %s\n", currCommand[i][0]);

        if (cmdArgs[i] > 0)
        {
            // printPath();
            char outFile[STR_SIZE];
            char *outLocal = outFile;
            getFilepath(currCommand[i][0], &outLocal);
            // printPath();
            // printf("RF: %d\n", redirectionFlag);
            // printf("SF: %s\n", outLocal);
            if (outLocal == NULL || (redirectionFlags[i] == 1 && redirectionValids[i] == 0))
            {
                write(STDERR_FILENO, error_message, strlen(error_message));
                PTR_FREE(command[i]);

                PTR_FREE(origPtr2Orig);

                ARR_FREE(currCommand[i], cmdArgs[i]);

                continue;
            }

            int forkRC = fork();
            if (forkRC < 0)
            {
                // Fork failed
                exit(1);
            }
            else if (forkRC == 0)
            {
                // child
                // printf("%s\n", currCommand[0]);
                // printf("Filepath = %s\n", startFile);
                if (redirectionValids[i] == 1)
                {
                    // printPath();
                    // printf("RF: %s\n", redirectionFilenames[i]);
                    open(redirectionFilenames[i], O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
                }
                execv(outLocal, currCommand[i]);
                exit(1);
            }
            else
            {
                int status;
                int wpid = waitpid(forkRC, &status, 0); // wait for child to exit
                if (wpid == -1)
                {
                    perror("waitpid failed");
                    exit(1);
                }
                PTR_FREE(command[i]);

                PTR_FREE(origPtr2Orig);
                ARR_FREE(currCommand[i], cmdArgs[i]);
            }
        }
    }
}

void promptPoller(FILE *file)
{
    while (1)
    {
        if (file == stdin)
            printf("wish> ");
        char *newLine = NULL;
        size_t num = 0;
        ssize_t ret = getline(&newLine, &num, file);
        if (ret <= 0 || newLine == NULL)
        {
            if (newLine)
            {
                free(newLine);
            }
            clearPath();
            exit(0);
        }
        // printf("File Line: %s\n", newLine);
        if (ret > 0)
        {
            if (newLine[ret - 1] == '\n')
            {
                newLine[ret - 1] = '\0';
                if (ret == 1)
                {
                    continue;
                }
            }
        }
        if (strcmp(newLine, "exit") == 0)
        {
            if (newLine)
            {
                free(newLine);
            }
            clearPath();
            exit(0);
        }
        else
        {
            parseExecuteCommand(newLine);
        }
    }
}

int main(int argc, char *argv[])
{
    initPath();
    if (argc == 2)
    {
        // batch mode
        if (access(argv[1], F_OK) != 0)
        {
            PRINT_ERROR;
            clearPath();
            exit(1);
        }

        FILE *file = fopen(argv[1], "r");
        promptPoller(file);
    }
    else if (argc == 1)
    {
        // interactive mode
        promptPoller(stdin);
    }
    else
    {
        clearPath();
        PRINT_ERROR;
        exit(1);
    }
    clearPath();
    return 0;
}
