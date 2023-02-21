# P4 application for table join between two relations
This P4 application has been developed for learning purposes to implement a table join between two relations within the dataplane. BMv2 & Mininet are used to run this P4 app.

This repository is using parts of the [p4lang/tutorials](https://github.com/p4lang/tutorials) repository to bootstrap the application.
## Design

## Howto
Start the P4 application
```bash
make
```
First, `exit` from the mininet console and stop the app:
```
make stop
# Cleanup
make clean
```