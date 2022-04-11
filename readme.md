# Unifi Youtube Killer

## Purpose

CLI to manage traffic filter state on my UDM Pro

## Background

So my kids sometimes need to use youtube for their classes, because my county in their infinite wisdom uses if for their online class content.  However other times I don't want them to have access.  So I needed a way to turn it on and off easily.

Luckley Ubiquity provides means to do this in their UI which is nice ( example below ).

![UI Interface](/assets/ui.jpg)

However this means whenever I need to make then change I have to log into this tool, navigate to the right page and then toggle the appropriate filter.  As a nerd I found this totally unacceptable and needed a better way.

Personally I use Home Assistant for my home automation and wanted to expose this state trigger as a button within it. This means I needed a bridge to manage auth , present current state, and then toggle the appropriate filter when I deem it necessary. So with this app I can now use it as a [command line switches within Home Assistant](https://www.home-assistant.io/integrations/switch.command_line/).

## Usage

```shell
NAME:
   Youtube - A new cli application

USAGE:
   Youtube [global options] command [command options] [arguments...]

VERSION:
   v0.0.1

DESCRIPTION:
   Grossly over engineered CLI to manage Unifi filter rules on UDM Pro

COMMANDS:
   status, s  Get current status
   allow, A   Enable allow rule
   block, B   Enable block rule
   help, h    Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help (default: false)
   --version, -v  print the version (default: false)

```

### Home Assistant

```yaml
switch:
  - platform: command_line
    switches:
      youtube_allow_list:
        unique_id: youtube_allow_list
        command_on: /config/youtube allow on
        command_off: /config/youtube allow off
        command_state: /config/youtube allow status

      youtube_block_list:
        unique_id: youtube_block_list
        command_on: /config/youtube block on
        command_off: /config/youtube block off
        command_state: /config/youtube block status
```

which results in something like this

![Home Assistant UI](/assets/hass.jpg)

and now I can block my kids youtube from anywhere in the world.  Score is Parents: 1, Kids: 0