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

void fetchAttestationReport(msg_report_req* msg_report_in, msg_response_resp* msg_report_out)
{   
    // int rc;	

    // printf("print debug in CGO...\nfd: %d, &payload: %lu(%p)\n", fd, &payload, &payload);

    // issue the custom SEV_SNP_GUEST_MSG_REPORT sys call to the sev driver
    // rc = ioctl(fd, 3223868161, payload);

    // if (rc < 0) {
    //     fprintf(stdout, "Failed to issue ioctl SEV_SNP_GUEST_MSG_REPORT\n");           
    // }

    // for (size_t i = 0; i < sizeof(snp_attestation_report); i++) {
    //     snp_attestation_report * p = &(msg_report_out->report);
    //     fprintf(stdout, "%02x", ((uint8_t *)(p))[i]);
    // }
    // printf("\n");
    // printf("status: %d, report_size: %d\n", msg_report_out->status, msg_report_out->report_size);
}

unsigned long getPointer(struct sev_snp_guest_request* p) {
    printf("pointer: %lu\n", p);
    return (unsigned long)p;
}