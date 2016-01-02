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
            $basic->compile()
        );
    }
}
