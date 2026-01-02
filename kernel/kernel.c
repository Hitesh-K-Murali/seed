void kernel_main()
{
    // This is a dummy kernel entry point
    char *video_memory = (char *)0xb8000;
    *video_memory = 'K';
}
