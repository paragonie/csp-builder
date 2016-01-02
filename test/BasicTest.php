<?php
use ParagonIE\CSPBuilder\CSPBuilder;
/**
 * 
 */
class BasicTest extends PHPUnit_Framework_TestCase
{
    public function testBasic()
    {
        $basic = CSPBuilder::fromFile(__DIR__.'/vectors/basic-csp.json');
        $basic->addSource('img-src', 'ytimg.com');
        $this->assertEquals(
            file_get_contents(__DIR__.'/vectors/basic-csp.out'),
            $basic->getCompiledHeader()
        );
        
        // We expect different output for ytimg.com when we disable legacy
        // browser support (i.e. Safari):
        $this->assertEquals(
            file_get_contents(__DIR__.'/vectors/basic-csp-no-old.out'),
            $basic
                ->disableOldBrowserSupport()
                ->getCompiledHeader()
        );
    }
}
