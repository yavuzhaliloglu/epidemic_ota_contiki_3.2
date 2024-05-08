#include "contiki.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "epidemic-ota.h"

#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "simple-udp.h"
#include "net/rpl/rpl-private.h"

#include "dev/flash.h"
#include "dev/rom-util.h"
#include "dev/watchdog.h"
/*----------------------------------------------------------------Defines----*/

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define UDP_PORT 1234
#define SERVICE_ID 190

#if TSCH_TIME_SYNCH
#include "net/mac/4emac/4emac-private.h"
#include "net/mac/4emac/4emac-buf.h"
#endif

/*--------------------------------------------------------------Variables----*/

// UDP connection variable
static struct simple_udp_connection udp_conn;
// Parent IP address
static const uip_ipaddr_t *parent_ip_address;
// Device ota_process_state
static enum device_state ota_process_state = STATE_REQUEST;

static const uint8_t packet_size = 80;
/*--------------------------------------------------------------Functions----*/

// print a buffer as hexadecimals
void printBufferHex(uint8_t *buffer, uint16_t len)
{
    for (uint16_t i = 0; i < len; i++)
    {
        if (i % 16 == 0 && i != 0)
        {
            printf("\n");
            if (i % 256 == 0)
                printf("\n");
        }

        printf("%02X ", buffer[i]);
    }
}
void print_packet_status(struct ota_packet *p)
{
    PRINTF("PRINT_PACKET_STATUS: Packet Status: \n");
    PRINTF("PRINT_PACKET_STATUS: p->msg_type: %02X\n", p->msg_type);
    PRINTF("PRINT_PACKET_STATUS: p->fw_version: %ld\n", p->fw_version);
    PRINTF("PRINT_PACKET_STATUS: p->fw_size: %d\n", p->fw_size);
    PRINTF("PRINT_PACKET_STATUS: p->fw_total_fragment_num: %d\n", p->fw_total_fragment_num);
    PRINTF("PRINT_PACKET_STATUS: p->fw_fragment_size: %d\n", p->fw_fragment_size);
    PRINTF("PRINT_PACKET_STATUS: p->data->len: %d\n", p->data.len);
    PRINTF("PRINT_PACKET_STATUS: p->data->buf:\n");
    printBufferHex(p->data.buf, p->data.len);
    PRINTF("\n\n");
}

// print current device state
void get_device_state(enum device_state state)
{
    PRINTF("GET_DEVICE_STATE: Device State is: ");
    switch (state)
    {
    case STATE_REQUEST:
        PRINTF("STATE_REQUEST\n");
        break;
    case STATE_UPDATE_CLIENT:
        PRINTF("STATE_UPDATE_CLIENT\n");
        break;
    case STATE_UPDATE_SERVER:
        PRINTF("STATE_UPDATE_SERVER\n");
        break;
    default:
        PRINTF("State ERROR!\n");
        break;
    }
}

// // control message type
// static uint8_t control_msg_type(uint8_t msg_type)
// {
//     if (msg_type == OTA_REQUEST || msg_type == OTA_RESPONSE || msg_type == OTA_DATA_PACKET || msg_type == OTA_PACKET_REQUEST)
//     {
//         return 1;
//     }

//     return 0;
// }

// get this program's firmware version.
// TODO: DÜZENLENECEK, FLASH BELLEKTEKI FIRMWARE VERSIYONUNU ALACAK.s
uint32_t get_firmware_version()
{
    return 1;
}

// get this program's firmware size.
// TODO: DÜZENLENECEK, FLASH BELLEKTEKI FIRMWARE SIZE'I ALACAK.
uint16_t get_firmware_size()
{
    return 128;
}

// create a request content buffer
uint8_t prepare_request_packet(struct ota_packet *p, uint8_t msg_type)
{
    uint8_t buf[OTA_MAX_DATA_SIZE];
    PRINTF("PREPARE_REQUEST_PACKET: preparing REQUEST packet.\n");

    p->msg_type = msg_type;
    p->fw_version = get_firmware_version();
    p->fw_size = 0;
    p->fw_total_fragment_num = 0;
    p->fw_fragment_size = 0;
    p->data.len = 64;
    memcpy(p->data.buf, buf, p->data.len);

    print_packet_status(p);

    if (p->msg_type && p->fw_version)
    {
        PRINTF("PREPARE_REQUEST_PACKET: Preparing REQUEST packet is successful.\n");
        return 1;
    }

    PRINTF("PREPARE_REQUEST_PACKET: Preparing REQUEST packet is failed!\n");
    return 0;
}

// create a response content buffer
uint8_t prepare_response_packet(struct ota_packet *p, uint8_t msg_type)
{
    uint8_t buf[OTA_MAX_DATA_SIZE];
    PRINTF("PREPARE_REQUEST_PACKET: preparing RESPONSE packet.\n");

    p->msg_type = msg_type;
    p->fw_version = get_firmware_version();
    p->fw_size = get_firmware_size();
    p->fw_total_fragment_num = (get_firmware_size() / OTA_MAX_DATA_SIZE);
    p->fw_fragment_size = OTA_MAX_DATA_SIZE;
    p->data.len = 64;
    memcpy(p->data.buf, buf, p->data.len);

    print_packet_status(p);

    if (!p->msg_type || !p->fw_version || !p->fw_size || !p->fw_total_fragment_num || !p->fw_fragment_size)
    {
        PRINTF("PREPARE_REQUEST_PACKET: Preparing RESPONSE packet is successful.\n");
        return 0;
    }

    PRINTF("PREPARE_REQUEST_PACKET: Preparing RESPONSE packet is failed!\n");
    return 1;
}

// create a packet request content buffer
uint8_t prepare_packet_request_packet(struct ota_packet *p, uint8_t msg_type)
{
    return 1;
}

// create a data packet content buffer
static uint8_t prepare_data_packet(struct ota_packet *p, uint8_t msg_type)
{
    return 1;
}

// prepare a packet with given data and modes, it returns 0 if the preparing packet is failed, returns 1 if preparing packet is successful
static uint8_t prepare_ota_packet(struct ota_packet *p, uint8_t msg_type)
{
    uint8_t is_packet_prepared;
    PRINTF("PREPARE_OTA_PACKET: msg_type: %02X\n", msg_type);

    switch (msg_type)
    {
    case OTA_REQUEST:
        is_packet_prepared = prepare_request_packet(p, msg_type);
        break;

    case OTA_RESPONSE:
        is_packet_prepared = prepare_response_packet(p, msg_type);
        break;

    case OTA_PACKET_REQUEST:
        is_packet_prepared = prepare_packet_request_packet(p, msg_type);
        break;

    case OTA_DATA_PACKET:
        is_packet_prepared = prepare_data_packet(p, msg_type);
        break;

    default:
        PRINTF("PREPARE_OTA_PACKET: Unsupported message type!\n");
        is_packet_prepared = 0;
        break;
    }

    if (is_packet_prepared)
    {
        return 1;
    }
    PRINTF("PREPARE_OTA_PACKET:packet cannot created!\n");
    return 0;
}

// create packet, transfer packet data into given buffer, it returns 0 if the preparing packet is failed, returns 1 if preparing packet is successful
uint8_t create_ota_packet(uint8_t *buf, uint8_t len, struct ota_packet *p)
{
    uint8_t cur_len = 0;
    print_packet_status(p);

    // add message type to packet
    if ((len - cur_len) >= 1)
    {
        buf[cur_len] = p->msg_type;
        cur_len++;
    }
    else
    {
        PRINTF("CREATE_OTA_PACKET: Message Type cannot added packet!\n");
        return 0;
    }

    // add firmware version to packet
    if ((len - cur_len) >= sizeof(uint32_t))
    {
        memcpy(&buf[cur_len], &p->fw_version, sizeof(uint32_t));
        cur_len += sizeof(uint32_t);
    }
    else
    {
        PRINTF("CREATE_OTA_PACKET: Firmware version cannot added packet!\n");
        return 0;
    }

    // add firmware size to packet
    if ((len - cur_len) >= sizeof(uint16_t))
    {
        memcpy(&buf[cur_len], &p->fw_size, sizeof(uint16_t));
        cur_len += sizeof(uint16_t);
    }
    else
    {
        PRINTF("CREATE_OTA_PACKET: Firmware size cannot added packet!\n");
        return 0;
    }

    // add firmware's total fragment number to packet
    if ((len - cur_len) >= 1)
    {
        buf[cur_len] = p->fw_total_fragment_num;
        cur_len++;
    }
    else
    {
        PRINTF("CREATE_OTA_PACKET: Firmware's total fragment number cannot added packet!\n");
        return 0;
    }

    // add firmware's fragment size to packet
    if ((len - cur_len) >= 1)
    {
        buf[cur_len] = p->fw_fragment_size;
        cur_len++;
    }
    else
    {
        PRINTF("CREATE_OTA_PACKET: Firmware fragment size cannot added packet!\n");
        return 0;
    }

    // add firmware data len to packet
    if ((len - cur_len) >= 1)
    {
        buf[cur_len] = p->data.len;
        cur_len++;
    }
    else
    {
        PRINTF("CREATE_OTA_PACKET: Firmware data len cannot added packet!\n");
        return 0;
    }

    // add firmware data to packet
    if ((len - cur_len) >= p->data.len)
    {
        memcpy(&buf[cur_len], &p->data.buf, p->data.len);
        cur_len += p->data.len;
    }
    else
    {
        PRINTF("CREATE_OTA_PACKET: Firmware data buf cannot added packet!\n");
        return 0;
    }

    PRINTF("CREATE_OTA_PACKET: Packet created. Packet is: \n");
    printBufferHex(buf, len);
    PRINTF("\n");

    return 1;
}

static struct ota_packet buf_to_ota_packet(uint8_t *buf, uint16_t len)
{
    uint16_t cur_len = 0;
    struct ota_packet p;

    if ((len - cur_len) >= 1)
    {
        p.msg_type = buf[cur_len];
        cur_len++;
    }

    if ((len - cur_len) >= sizeof(uint32_t))
    {
        memcpy(&p.fw_version, &buf[cur_len], sizeof(uint32_t));
        cur_len += sizeof(uint32_t);
    }

    if ((len - cur_len) >= sizeof(uint16_t))
    {
        memcpy(&p.fw_size, &buf[cur_len], sizeof(uint16_t));
        cur_len += sizeof(uint16_t);
    }

    if ((len - cur_len) >= 1)
    {
        p.fw_total_fragment_num = buf[cur_len];
        cur_len++;
    }

    if ((len - cur_len) >= 1)
    {
        p.fw_fragment_size = buf[cur_len];
        cur_len++;
    }

    if ((len - cur_len) >= 1)
    {
        p.data.len = buf[cur_len];
        cur_len++;
    }

    if ((len - cur_len) >= p.data.len)
    {
        memcpy(&p.data.buf, &buf[cur_len], p.data.len);
        cur_len += p.data.len;
    }

    return p;
}

// UDP connection callback handler
static void
udp_callback(struct simple_udp_connection *c,
             const uip_ipaddr_t *sender_addr,
             uint16_t sender_port,
             const uip_ipaddr_t *receiver_addr,
             uint16_t receiver_port,
             const uint8_t *data,
             uint16_t datalen)
{
    PRINTF("\nUDP_CALLBACK: Data received on port %d from port %d with length %d.\n", receiver_port, sender_port, datalen);
    struct ota_packet incoming_packet = buf_to_ota_packet(data, datalen);
    struct ota_packet packet_to_send;
    uint8_t buf_to_send[80];

    print_packet_status(&incoming_packet);

    switch (incoming_packet.msg_type)
    {
    case OTA_REQUEST:
        PRINTF("UDP_CALLBACK: Incoming packet type is OTA_REQUEST.\n");
        if (prepare_ota_packet(&packet_to_send, OTA_RESPONSE))
        {
            if (create_ota_packet(buf_to_send, packet_size, &packet_to_send))
            {
                PRINTF("Packet is created. Sending to ");
                PRINT6ADDR(parent_ip_address);
                PRINTF("\n");

                // send packet
                simple_udp_sendto(c, buf_to_send, sizeof(buf_to_send), sender_addr);
            }
        }
        break;

    case OTA_RESPONSE:
        PRINTF("UDP_CALLBACK: Incoming packet type is OTA_RESPONSE.\n");
        if (prepare_ota_packet(&packet_to_send, OTA_PACKET_REQUEST))
        {
            if (create_ota_packet(buf_to_send, packet_size, &packet_to_send))
            {
                PRINTF("Packet is created. Sending to ");
                PRINT6ADDR(parent_ip_address);
                PRINTF("\n");

                // send packet
                simple_udp_sendto(c, buf_to_send, sizeof(buf_to_send), sender_addr);
            }
        }
        break;

    case OTA_PACKET_REQUEST:
        PRINTF("UDP_CALLBACK: Incoming packet type is OTA_PACKET_REQUEST.\n");
        break;

    case OTA_DATA_PACKET:
        PRINTF("UDP_CALLBACK: Incoming packet type is OTA_DATA_PACKET.\n");
        break;

    default:
        PRINTF("UDP_cALLBACK: Incoming packet type is invalid!\n");
        break;
    }
}

/*--------------------------------------------------------------Processes----*/

PROCESS(request_process, "Epidemic Routing Request Process");
PROCESS(update_process, "Epidemic Routing Update Process");

/*--------------------------------------------------------Thread(Request)----*/

PROCESS_THREAD(request_process, ev, data)
{
    // request timer, synch timer
    static struct etimer et_request;
    // static int counter_request = 0;
    static struct etimer et_identify;
    // init an ota packet
    static struct ota_packet p;
    // get size of ota packet
    static uint8_t udp_buf[80];

    PROCESS_BEGIN();
    PROCESS_PAUSE();
    PRINTF("1\n");
    // set synch timer and wait until node is synchronized.
    etimer_set(&et_identify, AUTHENTICATION_INTERVAL * CLOCK_SECOND);
    PRINTF("2\n");
    while (!foure_control.authenticated || default_instance == NULL || default_instance->current_dag->preferred_parent == NULL)
    {
        PROCESS_WAIT_UNTIL(etimer_expired(&et_identify));
        etimer_set(&et_identify, AUTHENTICATION_INTERVAL * CLOCK_SECOND);
        PRINTF("REQUEST_PROCESS: Waiting for synch...\n");
    }
    PRINTF("3\n");
    // after the synchronization, get parent from default instance and get it's IP address.
    rpl_parent_t *parent = default_instance->current_dag->preferred_parent;
    parent_ip_address = rpl_get_parent_ipaddr(parent);
    PRINTF("4\n");
    // set the UDP connection with port UDP_PORT
    // uint8_t is_udp_connected = ;
    // check if the connection is available, if not, exit from process.
    if (!simple_udp_register(&udp_conn, UIP_HTONS(UDP_PORT), NULL, UIP_HTONS(UDP_PORT), udp_callback))
    {
        PRINTF("REQUEST_PROCESS: UDP Connection Error!\n");
        PROCESS_EXIT();
    }
    PRINTF("5\n");
    // set the request timer
    etimer_set(&et_request, REQUEST_SEND_INTERVAL * CLOCK_SECOND);
    PRINTF("6\n");
    while (1)
    {
        PROCESS_YIELD();
        PRINTF("7\n");
        // control device ota_process_state, if ota_process_state is request, send request to parent
        if (ota_process_state == STATE_REQUEST)
        {
            PRINTF("8\n");
            // prepare request message
            // uint8_t is_packet_prepared = ;

            // control if packet is prepared, if not, dont send packet
            if (prepare_ota_packet(&p, OTA_REQUEST))
            {
                PRINTF("9\n");
                // if packed is prepared, init a buffer of size ota packet and fill it with packet data
                // uint8_t is_packet_created = ;

                // control if packet created, if not dont send packet
                if (create_ota_packet(udp_buf, packet_size, &p))
                {
                    PRINTF("Packet is created. Sending to ");
                    PRINT6ADDR(parent_ip_address);
                    PRINTF("\n");

                    // send packet
                    simple_udp_sendto(&udp_conn, udp_buf, sizeof(udp_buf), parent_ip_address);
                }
                else
                    PRINTF("REQUEST_PROCESS: packet cannot created!\n");
            }
            else
                PRINTF("REQUEST_PROCESS: packet cannot prepared!\n");

            // send request message to parent
            PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et_request));
            etimer_reset(&et_request);
        }
        // if ota_process_state is STATE_UPDATE_CLIENT or STATE_UPDATE_SERVER, don't do anything, just wait until ota process ends.
        else if (ota_process_state == STATE_UPDATE_CLIENT || ota_process_state == STATE_UPDATE_SERVER)
        {
            etimer_stop(&et_request);
            PRINTF("REQUEST_PROCESS: Device ota_process_state is %02X. So waiting for ota_process_state changing...\n", ota_process_state);
            PROCESS_WAIT_EVENT_UNTIL(ota_process_state == STATE_REQUEST);
            etimer_reset(&et_request);
        }
        else
        {
            PROCESS_YIELD();
        }
    }

    PROCESS_END();
}

/*---------------------------------------------------------Thread(Update)----*/

PROCESS_THREAD(update_process, ev, data)
{
    static struct etimer et_update;
    static int counter_update = 0;

    PROCESS_BEGIN();
    PROCESS_PAUSE();

    while (1)
    {
        etimer_set(&et_update, 3 * CLOCK_SECOND);
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et_update));
        PRINTF("Hello World %d FROM UPDATE PROCESS\n", counter_update++);
        etimer_reset(&et_update);

        if (counter_update == 3)
        {
            process_start(&request_process, NULL);
            counter_update = 0;
            break;
        }
    }

    PROCESS_END();
}
/*-------------------------------------------------------------------Init----*/
void start_epidemic_ota()
{
    process_exit(&request_process);
    process_start(&request_process, NULL);
}