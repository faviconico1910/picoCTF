---
Look at the source code: 
```
void (*check)(char*, size_t) = hard_checker;
int fun[10] = {0};

void vuln()
{
  char story[128];
  int num1, num2;

  printf("Tell me a story and then I'll tell you if you're a 1337 >> ");
  scanf("%127s", story);
  printf("On a totally unrelated note, give me two numbers. Keep the first one less than 10.\n");
  scanf("%d %d", &num1, &num2);

  if (num1 < 10)
  {
    fun[num1] += num2;
  }

  check(story, strlen(story));
}
``` 
In short, the program takes input of an char array and other two intergers from us. Then, if ``` num1 < 10 ``` do ``` fun[num1] += num2 ```. We can see ``` check ``` function points to ``` hard_checker ```:
```
int calculate_story_score(char *story, size_t len)
{
  int score = 0;
  for (size_t i = 0; i < len; i++)
  {
    score += story[i];
  }

  return score;
}

void hard_checker(char *story, size_t len)
{
  if (calculate_story_score(story, len) == 13371337)
  {
    char buf[FLAGSIZE] = {0};
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL)
    {
      printf("%s %s", "Please create 'flag.txt' in this directory with your",
                      "own debugging flag.\n");
      exit(0);
    }

    fgets(buf, FLAGSIZE, f); // size bound read
    printf("You're 13371337. Here's the flag.\n");
    printf("%s\n", buf);
  }
  else
  {
    printf("You've failed this class.");
  }
}
```
However, we obviously can't have the result of ``` calculate_story_score ``` = 13371337 because the maximum elements of ``` story ``` array is 128. 
Therefore, we have to make the ``` check ``` point to another function.
Specifically, it is ``` easy_checker ```:
```
void easy_checker(char *story, size_t len)
{
  if (calculate_story_score(story, len) == 1337)
  {
    char buf[FLAGSIZE] = {0};
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL)
    {
      printf("%s %s", "Please create 'flag.txt' in this directory with your",
                      "own debugging flag.\n");
      exit(0);
    }

    fgets(buf, FLAGSIZE, f); // size bound read
    printf("You're 1337. Here's the flag.\n");
    printf("%s\n", buf);
  }
  else
  {
    printf("You've failed this class.");
  }
}
```
There is a bug in this chunk of code. If num1 is a negative integer, it still matches the condition which we can leverage to change data
```
  if (num1 < 10)
  {
    fun[num1] += num2;
  }
```
As we can see, we are able to make the result become ``` 1337 ```. First, debug in gdb. 
```
gef➤  p&hard_checker
$1 = (<text variable, no debug info> *) 0x8049436 <hard_checker>
gef➤  p&easy_checker
$2 = (<text variable, no debug info> *) 0x80492fc <easy_checker>
gef➤  p/d 0x8049436-0x80492fc
$3 = 314
```
```
gef➤  x/50xg 0x804c040
0x804c040 <check>:      0x0000000008049436    0x0000000000000000
0x804c050:      0x0000000000000000      0x0000000000000000
  ...
0x804c080 <fun>:        0x0000000000000000      0x0000000000000000
```
The check funtion currently points to ``` hard_checker ```.
If we type in ``` num1 ``` = -16, we can reach the ``` hard_checker``` and then wisely change it to ``` easy_checker ```. 
Finally, think about how to make the result of ``` calculate_story_score ``` become 1337.

My script: [script.py](https://github.com/faviconico1910/picoCTF/blob/master/function-overwrite/function_overwrite.py)
