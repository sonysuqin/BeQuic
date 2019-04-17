//
//  ViewController.m
//  quic_test
//
//  Created by testtest on 2019/4/15.
//  Copyright © 2019 sohu. All rights reserved.
//

#import "ViewController.h"
#import "libs/be_quic.h"


@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.

    const char* url = "http://10.2.9.251:6121";
    int handle = be_quic_open(url, NULL, NULL, 0, NULL, 0, 1, 1000);
    int size = 0;
    unsigned long filesize = 0;
    unsigned char* buffer = (unsigned char *)malloc(1024 * 10);
    while((size = be_quic_read(handle, buffer, 1024 * 10, 1000)) > 0) {
        NSLog(@"size = %d", size);
        filesize += size;
    }
    NSLog(@"filesize = %ld", filesize);
    free(buffer);
    be_quic_close(handle);
}


@end
