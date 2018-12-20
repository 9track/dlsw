
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFSIZE         1024

/* Message types */

#define CANUREACH       0x03                            /* Can U Reach Station */
#define ICANREACH       0x04                            /* I Can Reach Station */
#define REACH_ACK       0x05                            /* Reach Acknowledgment */
#define DGRMFRAME       0x06                            /* Datagram Frame */
#define XIDFRAME        0x07                            /* XID Frame */
#define CONTACT         0x08                            /* Contact Remote Station */
#define CONTACTED       0x09                            /* Remote Station Contacted */
#define RESTART_DL      0x10                            /* Restart Data Link */
#define DL_RESTARTED    0x11                            /* Data Link Restarted */
#define ENTER_BUSY      0x0C                            /* Enter Busy */
#define EXIT_BUSY       0x0D                            /* Exit Busy */
#define INFOFRAME       0x0A                            /* Information (I) Frame */
#define HALT_DL         0x0E                            /* Halt Data Link */
#define DL_HALTED       0x0F                            /* Data Link Halted */
#define NETBIOS_NQ      0x12                            /* NETBIOS Name Query */
#define NETBIOS_NR      0x13                            /* NETBIOS Name Recog */
#define DATAFRAME       0x14                            /* Data Frame */
#define HALT_DL_NOACK   0x19                            /* Halt Data Link with no Ack */
#define NETBIOS_ANQ     0x1A                            /* NETBIOS Add Name Query */
#define NETBIOS_ANR     0x1B                            /* NETBIOS Add Name Response */
#define KEEPALIVE       0x1D                            /* Transport Keepalive Message */
#define CAP_EXCHANGE    0x20                            /* Capabilities Exchange */
#define IFCM            0x21                            /* Independent Flow Control Message */
#define TEST_CIRC_REQ   0x7A                            /* Test Circuit Request */
#define TEST_CIRC_RSP   0x7B                            /* Test Circuit Response */

#if 0
/* States */

#define CIRCUIT_ESTABLISHED
#define CIRCUIT_PENDING
#define CIRCUIT_RESTART
#define CIRCUIT_START
#define CONNECTED
#define CONNECT_PENDING
#define CONTACT_PENDING
#define DISCONNECTED
#define DISCONNECT_PENDING
#define HALT_PENDING
#define HALT_PENDING_NOACK
#define RESTART_PENDING
#define RESOLVE_PENDING

/* Events */

#define DLC_CONTACTED
//#define DLC_DGRM
#define DLC_ERROR
#define DLC_INFO
#define DLC_DL_HALTED
#define DLC_DL_STARTED
#define DLC_RESET
#define DLC_RESOLVE_C
#define DLC_RESOLVED
#define DLC_XID
#define XPORT_FAILURE
#define CS_TIMER_EXP

/* Actions */

#define DLC_CONTACT
//#define DLC_DGRM **
#define DLC_ENTER_BUSY
#define DLC_EXIT_BUSY
#define DLC_HALT_DL
#define DLC_INFO **
#define DLC_RESOLVE
#define DLC_RESOLVE_R
#define DLC_START_DL
#define DLC_XID **
#endif

/* SSP flags */

#define SSPex           0x80                            /* explorer message */

/* Frame direction */

#define DIR_TGT         0x01                            /* origin to target */
#define DIR_ORG         0x02                            /* target to origin */

/* Header constants */

#define DLSW_VER        0x31                            /* DLSw version 1 */
#define LEN_CTRL        72                              /* control header length */
#define LEN_INFO        16                              /* info header length */

#define DLSW_PORT       2065

/* Common header fields */

#define HDR_VER         0x00                            /* Version Number */
#define HDR_HLEN        0x01                            /* Header Length */
#define HDR_MLEN        0x02                            /* Message Length */
#define HDR_RDLC        0x04                            /* Remote Data Link Correlator */
#define HDR_RDPID       0x08                            /* Remote DLC Port ID */
#define HDR_MTYP        0x0E                            /* Message Type */
#define HDR_FCB         0x0F                            /* Flow Control Byte */

/* Control header fields */

#define HDR_PID         0x10                            /* Protocol ID */
#define HDR_NUM         0x11                            /* Header Number */
#define HDR_LFS         0x14                            /* Largest Frame Size */
#define HDR_SFLG        0x15                            /* SSP Flags */
#define HDR_CP          0x16                            /* Circuit Priority */
#define HDR_TMAC        0x18                            /* Target MAC Address */
#define HDR_OMAC        0x1E                            /* Origin MAC Address */
#define HDR_OSAP        0x24                            /* Origin Link SAP */
#define HDR_TSAP        0x25                            /* Target Link SAP */
#define HDR_DIR         0x26                            /* Frame Direction */
#define HDR_DLEN        0x2A                            /* DLC Header Length */
#define HDR_ODPID       0x2C                            /* Origin DLC Port ID */
#define HDR_ODLC        0x30                            /* Origin Data Link Correlator */
#define HDR_OTID        0x34                            /* Origin Transport ID */
#define HDR_TDPID       0x38                            /* Target DLC Port ID */
#define HDR_TDLC        0x3C                            /* Target Data Link Correlator */
#define HDR_TTID        0x40                            /* Target Transport ID */

/* Flow control fields */

#define FCB_FCI         0x80                            /* Flow control indicator */
#define FCB_FCA         0x40                            /* Flow control acknowledge */
#define FCB_FCO         0x07                            /* Flow control operator */

#define FCO_RPT         0x00                            /* Repeat window operator */
#define FCO_INC         0x01                            /* Increment window operator */
#define FCO_DEC         0x02                            /* Decrement window operator */
#define FCO_RST         0x03                            /* Reset window operator */
#define FCO_HLV         0x04                            /* Halve window operator */

/* Capabilities Exchange Subfields */

#define CAP_VID         0x81                            /* Vendor ID */
#define CAP_VER         0x82                            /* DLSw Version */
#define CAP_IPW         0x83                            /* Initial Pacing Window */
#define CAP_VERS        0x84                            /* Version String */
#define CAP_MACX        0x85                            /* MAC Address Exclusivity */
#define CAP_SSL         0x86                            /* Supported SAP List */
#define CAP_TCP         0x87                            /* TCP Connections */
#define CAP_NBX         0x88                            /* NetBIOS Name Exclusivity */
#define CAP_MACL        0x89                            /* MAC Address List */
#define CAP_NBL         0x8A                            /* NetBIOS Name List */
#define CAP_VC          0x8B                            /* Vendor Context */

/* Packet data access macros */

#define GET16(p,w)      (((uint16_t) p[w]) | \
                        (((uint16_t) p[(w)+1]) << 8))
#define GET32(p,w)      (((uint32_t) p[w]) | \
                        (((uint32_t) p[(w)+1]) << 8) | \
                        (((uint32_t) p[(w)+2]) << 16) | \
                        (((uint32_t) p[(w)+3]) << 24))

#define PUT16(p,w,x)    p[w] = (x) & 0xFF; \
                        p[(w)+1] = ((x) >> 8) & 0xFF
#define PUT32(p,w,x)    p[w] = (x) & 0xFF; \
                        p[(w)+1] = ((x) >> 8) & 0xFF; \
                        p[(w)+2] = ((x) >> 16) & 0xFF; \
                        p[(w)+3] = ((x) >> 24) & 0xFF

typedef struct {
    int readfd;                                         /* read socket */
    int writefd;                                        /* write socket */
    int high_ip;                                        /* local host has higher ip */
    int fca_owed;                                       /* flow control ack owed */
    int init_window;
    int window;
    int granted;
    int flow_control;
    int actlu;
    uint32_t dlc;                                       /* data link correlator */
    uint32_t dlc_pid;                                   /* DLC port id */
} PEER_t;

/*
 * error - wrapper for perror
 */
void error(char *msg)
{
    perror(msg);
    exit(1);
}

void send_capabilities(PEER_t *peer, unsigned char *buf)
{
    unsigned int off = LEN_CTRL + 4;
    int n;                                              /* message byte size */

    peer->flow_control = 0;

    buf[off++] = 0x05;                                  /* Vendor ID */
    buf[off++] = CAP_VID;
    buf[off++] = 0x00;
    buf[off++] = 0x00;
    buf[off++] = 0x00;

    buf[off++] = 0x04;                                  /* DLSw Version */
    buf[off++] = CAP_VER;
    buf[off++] = 0x02;
    buf[off++] = 0x00;

    buf[off++] = 0x04;                                  /* Initial Pacing Window */
    buf[off++] = CAP_IPW;
    buf[off++] = 0x00;
    buf[off++] = 0x14;

    buf[off++] = 0x12;                                  /* Supported SAP List */
    buf[off++] = CAP_SSL;
    buf[off++] = 0xFF;
    buf[off++] = 0xFF;
    buf[off++] = 0xFF;
    buf[off++] = 0xFF;
    buf[off++] = 0xFF;
    buf[off++] = 0xFF;
    buf[off++] = 0xFF;
    buf[off++] = 0xFF;
    buf[off++] = 0xFF;
    buf[off++] = 0xFF;
    buf[off++] = 0xFF;
    buf[off++] = 0xFF;
    buf[off++] = 0xFF;
    buf[off++] = 0xFF;
    buf[off++] = 0xFF;
    buf[off++] = 0xFF;

    buf[off++] = 0x03;                                  /* TCP Connections */
    buf[off++] = CAP_TCP;
    buf[off++] = 0x01;
    
    PUT16(buf, LEN_CTRL, htons(off - LEN_CTRL));
    PUT16(buf, LEN_CTRL + 2, htons(0x1520));

    buf[HDR_VER] = DLSW_VER;
    buf[HDR_HLEN] = LEN_CTRL;
    PUT16(buf, HDR_MLEN, htons(off - LEN_CTRL));
    buf[HDR_MTYP] = CAP_EXCHANGE;
    buf[HDR_PID] = 0x42;
    buf[HDR_NUM] = 0x01;
    buf[HDR_DIR] = DIR_TGT;
    
    n = write(peer->writefd, buf, off);
    if (n < 0)
        error("ERROR writing to socket");
    printf("--> CAP_EXCHANGE\r\n");
}

void process_capabilities(PEER_t *peer, unsigned char *buf)
{
    int close_read = 0;
    int close_write = 0;
    unsigned int msg_off = LEN_CTRL;
    unsigned int cap_len = ntohs(GET16(buf, msg_off));
    unsigned int gds_id = ntohs(GET16(buf, msg_off + 2));
    unsigned int off = msg_off + 4;
    int n;                                              /* message byte size */
    unsigned int len, typ;

    if (gds_id == 0x1521)
    {
        printf("capabilities response\r\n");
        return;
    }
    else if (gds_id != 0x1520)
    {
        printf("unknown capabilities exchange\r\n");
        return;
    }

    printf("cap_len = %d\r\n", cap_len);
    while (off < (cap_len + msg_off))
    {
        len = buf[off];
        typ = buf[off+1];
        printf("CAP: offset = %d, len = %d\r\n", off, len);
        switch (typ)
        {
            case CAP_VID:                               /* Vendor ID */
                printf("CAP: Vendor ID\r\n");
                break;

            case CAP_VER:                               /* DLSw Version */
                printf("CAP: DLSw Version\r\n");
                break;

            case CAP_IPW:                               /* Initial Pacing Window */
                printf("CAP: Initial Pacing Window\r\n");
                peer->init_window = ntohs(GET16(buf, off));
                peer->window = peer->init_window;
                peer->granted = 0;
                peer->fca_owed = 0;
                break;

            case CAP_VERS:                              /* Version String */
                printf("CAP: Version String\r\n");
                break;

            case CAP_MACX:                              /* MAC Address Exclusivity */
                printf("CAP: MAC Address Exclusivity\r\n");
                break;

            case CAP_SSL:                               /* Supported SAP List */
                printf("CAP: Supported SAP List\r\n");
                break;

            case CAP_TCP:                               /* TCP Connections */
                printf("CAP: TCP Connection\r\n");
                if ((buf[off+2] == 1) && (peer->readfd != peer->writefd))
                {
                    if (peer->high_ip)
                    {
                        close_read = 1;
                    }
                    else
                    {
                        close_write = 1;
                    }
                }
                break;

            case CAP_NBX:                               /* NetBIOS Name Exclusivity */
                printf("CAP: NetBIOS Name Exclusivity\r\n");
                break;

            case CAP_MACL:                              /* MAC Address List */
                printf("CAP: MAC Address List\r\n");
                break;

            case CAP_NBL:                               /* NetBIOS Name List */
                printf("CAP: NetBIOS Name List\r\n");
                break;

            case CAP_VC:                                /* Vendor Context */
                printf("CAP: Vendor Context\r\n");
                break;

            default:
                printf("CAP: Unknown 0x%02X\r\n", typ);
                break;
        }
        off = off + len;
    }

    PUT16(buf, HDR_MLEN, htons(0x0004));                /* Message Length */
    PUT16(buf, msg_off, htons(0x0004));                 /* GDS Length */
    PUT16(buf, msg_off + 2, htons(0x1521));             /* GDS ID = Capabilities Response */

    n = write(peer->writefd, buf, msg_off + 4);         /* send response */
    if (n < 0)
        error("ERROR writing to socket");
    printf("--> CAP_EXCHANGE(r)\r\n");

    if (close_read)
    {
        printf("Closing read socket\r\n");
        close(peer->readfd);
        peer->readfd = peer->writefd;
    }
    else if (close_write)
    {
        printf("Closing write socket\r\n");
        peer->writefd = peer->readfd;
    }
}

#if 0
void process_disconnected_event()
{
    switch (event)
    {
        case CANUREACH_cs:
            break;
    }
}

void process_event()
{
    switch (state)
    {
        case DISCONNECTED:
            process_disconnected_event();
            break;

        case RESOLVE_PENDING:
}

void process_canureach_ex()
{
}

void process_canureach_cs()
{
    switch (state)
    {
        case DISCONNECTED:
            state = RESOLVE_PENDING;
            if (ncp_started)
            {
                send_icanreach_cs();
                state = CIRCUIT_PENDING;
            }
            break;

        case CIRCUIT_START:
            break;

        default:
            // Invalid?
            break;
    }
}
#endif

void process_flow_control(PEER_t *peer, unsigned char *buf)
{
    if (buf[HDR_FCB] & FCB_FCI)
    {
        switch (buf[HDR_FCB] & FCB_FCO)
        {
            case FCO_RPT:
                peer->granted += peer->window;
                break;

            case FCO_INC:
                peer->window++;
                peer->granted += peer->window;
                break;

            case FCO_DEC:
                peer->window--;
                peer->granted += peer->window;
                break;

            case FCO_RST:
                peer->window = 0;
                peer->granted = 0;
                break;

            case FCO_HLV:
                if (peer->window > 1)
                {
                    peer->window = peer->window / 2;
                }
                peer->granted += peer->window;
                break;
        }
    }
    if (buf[HDR_FCB] & FCB_FCA)
    {
        peer->fca_owed = 0;
    }
    if (peer->fca_owed)
    {
        buf[HDR_FCB] = 0;
    }
    else
    {
        buf[HDR_FCB] = FCB_FCI | FCO_RPT;
        peer->fca_owed = 1;
    }
}

void process_packet(PEER_t *peer, unsigned char *buf)
{
    uint8_t msg_type = buf[HDR_MTYP];
    uint16_t msg_len = ntohs(GET16(buf, HDR_MLEN));
    int n;

    if (peer->flow_control)
    {
        process_flow_control(peer, buf);
    }

    switch (msg_type)
    {
        case CANUREACH:                                 /* Can U Reach Station */
            if (buf[HDR_SFLG] & SSPex)
                printf("<-- CANUREACH(ex)\r\n");
            else
                printf("<-- CANUREACH(cs)\r\n");
            PUT16(buf, HDR_MLEN, 0);
            buf[HDR_MTYP] = ICANREACH;
            buf[HDR_DIR] = DIR_ORG;
            PUT32(buf, HDR_RDLC, GET32(buf, HDR_ODLC));
            PUT32(buf, HDR_RDPID, GET32(buf, HDR_ODPID));
            n = write(peer->writefd, buf, LEN_CTRL);
            if (n < 0)
                error("ERROR writing to socket");
            if (buf[HDR_SFLG] & SSPex)
                printf("--> ICANREACH(ex)\r\n");
            else
                printf("--> ICANREACH(cs)\r\n");
            break;

        case REACH_ACK:
            printf("<-- REACH_ACK\r\n");
            peer->flow_control = 1;
#if 0
            PUT16(buf, HDR_MLEN, 0);
            buf[HDR_MTYP] = CONTACT;
            buf[HDR_DIR] = DIR_ORG;
            n = write(peer->writefd, buf, LEN_CTRL);
            if (n < 0)
                error("ERROR writing to socket");
            printf("--> CONTACT\r\n");
#endif
            break;

        case XIDFRAME:
            printf("<-- XIDFRAME\r\n");
            if (msg_len > 0)                            /* received XID? */
            {
                buf[HDR_MTYP] = CONTACT;
                buf[HDR_DIR] = DIR_ORG;
                PUT32(buf, HDR_RDLC, GET32(buf, HDR_ODLC));
                PUT32(buf, HDR_RDPID, GET32(buf, HDR_ODPID));
                n = write(peer->writefd, buf, LEN_CTRL+msg_len);
                if (n < 0)
                    error("ERROR writing to socket");
                printf("--> CONTACT\r\n");
            }
            else                                        /* no, NULL XID */
            {
                PUT16(buf, HDR_MLEN, htons(20));
                buf[HDR_DIR] = DIR_ORG;
                PUT32(buf, HDR_RDLC, GET32(buf, HDR_ODLC));
                PUT32(buf, HDR_RDPID, GET32(buf, HDR_ODPID));
                buf[LEN_CTRL+0] = 0x14;
                buf[LEN_CTRL+1] = 0x01;
                buf[LEN_CTRL+2] = 0;
                buf[LEN_CTRL+3] = 0;
                buf[LEN_CTRL+4] = 0;
                buf[LEN_CTRL+5] = 0;
                buf[LEN_CTRL+6] = 0;
                buf[LEN_CTRL+7] = 0;
                buf[LEN_CTRL+8] = 0;
                buf[LEN_CTRL+9] = 0;
                buf[LEN_CTRL+10] = 0;
                buf[LEN_CTRL+11] = 0;
                buf[LEN_CTRL+12] = 0;
                buf[LEN_CTRL+13] = 0;
                buf[LEN_CTRL+14] = 0;
                buf[LEN_CTRL+15] = 0;
                buf[LEN_CTRL+16] = 0;
                buf[LEN_CTRL+17] = 0;
                buf[LEN_CTRL+18] = 0;
                buf[LEN_CTRL+19] = 0;
                n = write(peer->writefd, buf, LEN_CTRL+20);
                if (n < 0)
                    error("ERROR writing to socket");
                printf("--> XIDFRAME\r\n");
            }
            break;

        case CONTACT:
            printf("<-- CONTACT\r\n");
            PUT16(buf, HDR_MLEN, 0);
            buf[HDR_MTYP] = CONTACTED;
            buf[HDR_DIR] = DIR_ORG;
            PUT32(buf, HDR_RDLC, GET32(buf, HDR_ODLC));
            PUT32(buf, HDR_RDPID, GET32(buf, HDR_ODPID));
            n = write(peer->writefd, buf, LEN_CTRL);
            if (n < 0)
                error("ERROR writing to socket");
            printf("--> CONTACTED\r\n");
            break;

        case CONTACTED:
            peer->actlu = 0;
            PUT16(buf, HDR_MLEN, htons(18));
            buf[HDR_HLEN] = LEN_INFO;
            buf[HDR_MTYP] = INFOFRAME;
            buf[HDR_DIR] = DIR_ORG;
            peer->dlc = GET32(buf, HDR_ODLC);
            peer->dlc_pid = GET32(buf, HDR_ODPID);
            PUT32(buf, HDR_RDLC, GET32(buf, HDR_ODLC));
            PUT32(buf, HDR_RDPID, GET32(buf, HDR_ODPID));
            buf[LEN_INFO+0] = 0x2C;                     /* FID2 */
            buf[LEN_INFO+1] = 0x00;
            buf[LEN_INFO+2] = 0x00;                     /* DAF */
            buf[LEN_INFO+3] = 0x08;                     /* OAF */
            buf[LEN_INFO+4] = 0x00;                     /* SNF */
            buf[LEN_INFO+5] = 0x01;                     /* SNF */

            buf[LEN_INFO+6] = 0x6B;                     /* request header */
            buf[LEN_INFO+7] = 0x80;
            buf[LEN_INFO+8] = 0x00;

            buf[LEN_INFO+9] = 0x11;                     /* ACTPU */
            buf[LEN_INFO+10] = 0x01;                    /* cold activation */
            buf[LEN_INFO+11] = 0x01;                    /* FM, TS profile */
            buf[LEN_INFO+12] = 0x05;                    /* PU type of SSCP */
            buf[LEN_INFO+13] = 0x12;                    /* SSCP id */
            buf[LEN_INFO+14] = 0x34;
            buf[LEN_INFO+15] = 0x56;
            buf[LEN_INFO+16] = 0x78;
            buf[LEN_INFO+17] = 0x9A;
            n = write(peer->writefd, buf, LEN_INFO+18);
            if (n < 0)
                error("ERROR writing to socket");
            printf("--> ACTPU\r\n");
            break;

        case INFOFRAME:
            printf("<-- INFOFRAME\r\n");
            if (!peer->actlu)
            {
                peer->actlu = 1;
                PUT16(buf, HDR_MLEN, htons(12));
                buf[HDR_HLEN] = LEN_INFO;
                buf[HDR_MTYP] = INFOFRAME;
                buf[HDR_DIR] = DIR_ORG;
                PUT32(buf, HDR_RDLC, peer->dlc);
                PUT32(buf, HDR_RDPID, peer->dlc_pid);
                buf[LEN_INFO+0] = 0x2C;                     /* FID2 */
                buf[LEN_INFO+1] = 0x00;
                buf[LEN_INFO+2] = 0x24;                     /* DAF */
                buf[LEN_INFO+3] = 0x08;                     /* OAF */
                buf[LEN_INFO+4] = 0x00;                     /* SNF */
                buf[LEN_INFO+5] = 0x02;                     /* SNF */

                buf[LEN_INFO+6] = 0x6B;                     /* request header */
                buf[LEN_INFO+7] = 0x80;
                buf[LEN_INFO+8] = 0x00;

                buf[LEN_INFO+9] = 0x0D;                     /* ACTLU */
                buf[LEN_INFO+10] = 0x01;                    /* cold activation */
                buf[LEN_INFO+11] = 0x01;                    /* FM, TS profile */
                n = write(peer->writefd, buf, LEN_INFO+12);
                if (n < 0)
                    error("ERROR writing to socket");
                printf("--> ACTLU\r\n");
            }
            break;

        case CAP_EXCHANGE:                              /* Capabilities Exchange */
            printf("<-- CAP_EXCHANGE\r\n");
            process_capabilities(peer, buf);
            break;
        
    }
}

int main(int argc, char **argv)
{
    int serverfd;                                       /* server socket */
    int clientlen;                                      /* byte size of client's address */
    int serverlen;                                      /* byte size of server's address */
    struct sockaddr_in peeraddr;                        /* peer's addr */
    struct sockaddr_in serveraddr;                      /* server's addr */
    struct sockaddr_in clientaddr;                      /* client addr */
    struct hostent *hostp;                              /* client host info */
    unsigned char buf[BUFSIZE];                         /* message buffer */
    char *hostaddrp;                                    /* dotted decimal host addr string */
    int optval;                                         /* flag value for setsockopt */
    int n;                                              /* message byte size */
    unsigned int rem;                                   /* packet remainder size */
    unsigned int read_size;
    PEER_t peer;

    /* 
     * socket: create the parent socket 
     */
    serverfd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverfd < 0) 
        error("ERROR opening socket");

    /* setsockopt: Handy debugging trick that lets 
     * us rerun the server immediately after we kill it; 
     * otherwise we have to wait about 20 secs. 
     * Eliminates "ERROR on binding: Address already in use" error. 
     */
    optval = 1;
    setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, 
	       (const void *)&optval , sizeof(int));

    /*
     * build the server's Internet address
     */
    bzero((char *) &serveraddr, sizeof(serveraddr));

    /* this is an Internet address */
    serveraddr.sin_family = AF_INET;

    /* let the system figure out our IP address */
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

    /* this is the port we will listen on */
    serveraddr.sin_port = htons((unsigned short)DLSW_PORT);

    /* 
     * bind: associate the parent socket with a port 
     */
    if (bind(serverfd, (struct sockaddr *) &serveraddr, 
	     sizeof(serveraddr)) < 0) 
        error("ERROR on binding");

    /* 
     * listen: make this socket ready to accept connection requests 
     */
    if (listen(serverfd, 1) < 0)
        error("ERROR on listen");

    /* 
     * accept: wait for a connection request 
     */
    clientlen = sizeof(clientaddr);
    peer.readfd = accept(serverfd, (struct sockaddr *) &clientaddr, &clientlen);
    if (peer.readfd < 0) 
        error("ERROR on accept");
    
    /* 
     * determine who sent the message 
     */
    hostaddrp = inet_ntoa(clientaddr.sin_addr);
    if (hostaddrp == NULL)
        error("ERROR on inet_ntoa\n");
    printf("new client at %s\n", hostaddrp);

    /*
     * determine the local address
     */
    serverlen = sizeof(serveraddr);
    getsockname(peer.readfd, (struct sockaddr *) &serveraddr, &serverlen);

    /*
     * display the local address
     */
    hostaddrp = inet_ntoa(serveraddr.sin_addr);
    if (hostaddrp == NULL)
        error("ERROR on inet_ntoa\n");
    printf("on interface %s\n", hostaddrp);

    /*
     * determine if we have the higher ip address
     */
    if (serveraddr.sin_addr.s_addr > clientaddr.sin_addr.s_addr)
        peer.high_ip = 1;
    else
        peer.high_ip = 0;

    /* connect to the server */
    peer.writefd = socket(AF_INET, SOCK_STREAM, 0);
    if (peer.writefd < 0) 
        error("ERROR opening socket");

    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = clientaddr.sin_addr.s_addr;
    serveraddr.sin_port = htons((unsigned short)DLSW_PORT);

    /* connect: create a connection with the server */
    if (connect(peer.writefd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) 
        error("ERROR connecting");

    /* 
     * send capabilities to the server
     */
    bzero(buf, BUFSIZE);
    send_capabilities(&peer, buf);

    while (1)
    {
        read_size = 0;

        /*
         * read the common header fields
         */
        n = read(peer.readfd, buf, LEN_INFO);
        if (n < 0) 
            error("ERROR reading from socket");
        read_size += n;

        /*
         * calculate remaining packet size
         */
        rem = buf[HDR_HLEN] - LEN_INFO;
        rem = rem + ntohs(GET16(buf, HDR_MLEN));

        if (rem > 0)
        {
            /*
            * read remainder of packet
            */
            n = read(peer.readfd, &buf[LEN_INFO], rem);
            if (n < 0) 
                error("ERROR reading from socket");
            read_size += n;
        }

        printf("Received %d bytes\r\n", read_size);

        /*
         * process packet
         */
        process_packet(&peer, buf);
    }

    close(peer.readfd);
}
