## Задание
Составить программу работы автомобильного брелока, открывающего машину, с использованием ЭЦП в условиях, когда канал связи полностью доступен любому прослушивающему (в том числе и в течение большого времени и попыток), также атакующий может повторить прослушанные данные. 

### Особенности решения

Брелок (или золумышленник) отправляет машине команду на открытие дверей. Автомобиль, приняв команду, начинает "испытание" - отправляет сгенерированный рандом брелоку, который тот должен подписать приватным RSA ключем, а затем выслать подпись автомобилю (только если брелок ранее отправлял команду на открытие дверей). Автомобиль проверяет с помощью публичного RSA ключа (пара приватному ключу на брелоке) подпись. Если она валидна, то двери открываются.

## Запускаем
### Требования

- Компилятор GCC с поддержкой С++11.
- Утилита cmake v3.16.3.
- OpenSSL 1.1.1f.
- ОС на базе Linux.

### Соборка и запуск

#### Сборка:

```bash
git clone -b hw2 --single-branch https://github.com/GeorgiyX/Decent-HW.git
cd Decent-HW
mkdir build
cd build
cmake .. && cmake --build .
```

#### Запуск:

Запускать программу нужно из корневой папки:

```bash
./build/hw-2
```

Скриншоты работы:

1. Удачный запуск (брелок создает корректные подписи рандома, которые можно проверить публичным ключем автомобиля).

![ExampleRunHW2](.img/ExampleRunHW2.png)

2. Не удачный запуск (приватный ключ брелока не соответствует публичному ключу автомобиля).

![ExampleRunHW2(invalid_key)](.img/ExampleRunHW2(invalid_key).png)

