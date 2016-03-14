# XSS Challenge

This is a security challenge I developed for [HackFortress](https://twitter.com/tf2shmoo)
at [DEF CON](https://www.defcon.org/) 2014. It scores your ability to craft an
XSS exploit.

[Try it out](https://xss-challenge.herokuapp.com) and
[let me know](https://twitter.com/jamesreggio) if you solve it.

![Challenge](/screenshot-1.png?raw=true)

## How to play

Open [the challenge](https://xss-challenge.herokuapp.com) in your browser.
Finding the instructions is (an easy) part of the challenge.

Your score is returned from `/stolen_data` and is based upon three concerns:

* Did you steal the correct information?
* Did you actually perform code injection in the browser?
* Did you do it without making the page appear compromised?

The backend runs a number of checks upon the compromised page usingr[`jsdom`](https://github.com/tmpvar/jsdom),
so it's not particularly easy to cheat.

## How to run locally

Ensure `./node_modules/.bin` is in your path, then run:

```bash
npm install
npm start
open http://localhost:3000
```
