#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include "snp-psp.h"

void fetchAttestationReport(int fd, msg_report_req* msg_report_in)
{
    msg_response_resp msg_report_out;
    
    int rc;	
    
    struct sev_snp_guest_request payload = {
        .req_msg_type = SNP_MSG_REPORT_REQ,
        .rsp_msg_type = SNP_MSG_REPORT_RSP,
        .msg_version = 1,        
        .request_len = sizeof(*msg_report_in),
        .request_uaddr = (uint64_t) (void*) msg_report_in,
        .response_len = sizeof(msg_report_out),
        .response_uaddr = (uint64_t) (void*) &msg_report_out,
        .error = 0
    };
    
    memset((void*) msg_report_in, 0, sizeof(*msg_report_in));        
    memset((void*) &msg_report_out, 0, sizeof(msg_report_out));

    // issue the custom SEV_SNP_GUEST_MSG_REPORT sys call to the sev driver
    rc = ioctl(fd, SEV_SNP_GUEST_MSG_REPORT, &payload);

    if (rc < 0) {
        fprintf(stdout, "Failed to issue ioctl SEV_SNP_GUEST_MSG_REPORT\n");           
    }

    for (size_t i = 0; i < sizeof(snp_attestation_report); i++) {
        snp_attestation_report * p = &msg_report_out.report;
        fprintf(stdout, "%02x", ((uint8_t *)(p))[i]);
    }
    printf("\n");
    printf("status: %d, report_size: %d\n", msg_report_out.status, msg_report_out.report_size);
}
