<?php
namespace ParagonIE\CSPBuilder;

use \Psr\Http\Message\MessageInterface;

class CSPBuilder
{
    const FORMAT_APACHE = 'apache';
    const FORMAT_NGINX = 'nginx';
    
    private $policies = [];
    private $needsCompile = true;
    private $compiled = '';
    private $reportOnly = false;
    protected $supportOldBrowsers = true;
    
    private static $directives = [
        'base-uri',
        'default-src',
        'child-src',
        'connect-uri',
        'font-uri',
        'form-action',
        'frame-ancestors',
        'frame-src',
        'img-src',
        'media-src',
        'object-src',
        'plugin-types',
        'script-src',
        'style-src'
    ];
    
    /**
     * @param array $policy
     */
    public function __construct(array $policy = [])
    {
        $this->policies = $policy;
    }
    
    /**
     * Compile the current policies into a CSP header
     * 
     * @return string
     */
    public function compile()
    {
        $ruleKeys = \array_keys($this->policies);
        if (\in_array('report-only', $ruleKeys)) {
            $this->reportOnly = !!$this->policies['report-only'];
        } else {
            $this->reportOnly = false;
        }
        
        $compiled = [];
        
        foreach(self::$directives as $dir) {
            if (\in_array($dir, $ruleKeys)) {
                $compiled []= $this->compileSubgroup(
                    $dir,
                    $this->policies[$dir]
                );
            }
        }
        
        if (!empty($this->policies['report-uri'])) {
            $compiled []= 'report-uri '.$this->policies['report-uri'].'; ';
        }
        if (!empty($this->policies['upgrade-insecure-requests'])) {
            $compiled []= 'upgrade-insecure-requests';
        }
        
        $this->compiled = \implode('', $compiled);
        $this->needsCompile = false;
        return $this->compiled;
    }
    
    /**
     * Add a source to our allow whitelist
     * 
     * @param string $dir
     * @param string $path
     * 
     * @return CSPBuilder
     */
    public function addSource($dir, $path)
    {
        switch ($dir) {
            case 'child':
            case 'frame':
            case 'frame-src':
                if ($this->supportOldBrowsers) {
                    $this->policies['child-src']['allow'][] = $path;
                    $this->policies['frame-src']['allow'][] = $path;
                    return $this;
                }
                $dir = 'child-src';
                break;
            case 'connect':
            case 'socket':
            case 'websocket':
                $dir = 'connect-src';
                break;
            case 'font':
            case 'fonts':
                $dir = 'font-src';
                break;
            case 'form':
            case 'forms':
                $dir = 'form-action';
                break;
            case 'ancestor':
            case 'parent':
                $dir = 'frame-ancestors';
                break;
            case 'img':
            case 'image':
            case 'image-src':
                $dir = 'img-src';
                break;
            case 'media':
                $dir = 'media-src';
                break;
            case 'object':
                $dir = 'object-src';
                break;
            case 'js':
            case 'javascript':
            case 'script':
            case 'scripts':
                $dir = 'script-src';
                break;
            case 'style':
            case 'css':
            case 'css-src':
                $dir = 'style-src';
                break;
        }
        $this->policies[$dir]['allow'][] = $path;
        return $this;
    }
    
    /**
     * Add a directive if it doesn't already exist
     * 
     * If it already exists, do nothing
     * 
     * @param string $key
     * @param mixed $value
     * 
     * @return CSPBuilder
     */
    public function addDirective($key, $value = null)
    {
        if ($value === null) {
            if (!isset($this->policies[$key])) {
                $this->policies[$key] = true;
            }
        } elseif (empty($this->policies[$key])) {
            $this->policies[$key] = $value;
        }
    }
    
    /**
     * Add a plugin type to be added
     * 
     * @param string $mime
     * @return CSPBuilder
     */
    public function allowPluginType($mime = 'text/plain')
    {
        $this->policies['plugin-types']['types'] []= $mime;
        
        $this->needsCompile = true;
        return $this;
    }
    
    /**
     * Disable old browser support (e.g. Safari)
     * 
     * @return CSPBuilder
     */
    public function disableOldBrowserSupport()
    {
        $this->needsCompile = $this->supportOldBrowsers !== false;
        $this->supportOldBrowsers = false;
        return $this;
    }
    
    /**
     * Enable old browser support (e.g. Safari)
     * 
     * This is enabled by default
     * 
     * @return CSPBuilder
     */
    public function enableOldBrowserSupport()
    {
        $this->needsCompile = $this->supportOldBrowsers !== true;
        $this->supportOldBrowsers = true;
        return $this;
    }
    
    /**
     * Factory method - create a new CSPBuilder object from a JSON file
     * 
     * @param string $filename
     * @return CSPBuilder
     */
    public static function fromFile($filename = '')
    {
        if (!file_exists($filename)) {
            throw new \Exception($filename.' does not exist');
        }
        $json = \file_get_contents($filename);
        $array = \json_decode($json, true);
        return new CSPBuilder($array);
    }
    
    /**
     * Get the formatted CSP header 
     * 
     * @return string
     */
    public function getCompiledHeader()
    {
        if ($this->needsCompile) {
            $this->compile();
        }
        return $this->compiled;
    }
    
    /**
     * Get an associative array of headers to return.
     * 
     * @param type $legacy
     * @return string[]
     */
    public function getHeaderArray($legacy = true)
    {
        if ($this->needsCompile) {
            $this->compile();
        }
        $return = [];
        foreach ($this->getHeaderKeys($legacy) as $key) {
            $return[$key] = $this->compiled;
        }
        return $return;
    }
    
    /**
     * Add a new hash to the existing CSP
     * 
     * @param string $directive
     * @param string $script
     * @param string $algo
     * @return string
     */
    public function hash($directive = 'script-src', $script = '', $algo = 'sha256')
    {
        $ruleKeys = \array_keys($this->policies);
        if (\in_array($directive, $ruleKeys)) {
            $hash = \base64_encode(\hash($algo, $script, true));
            $this->policies[$directive]['hashes'] []= [
                $algo => \strtr($hash, '+/', '-_')
            ];
        }
        return $this;
    }
    
    /**
     * Add a new (precalculated) base64-encoded hash to the existing CSP
     * 
     * @param string $directive
     * @param string $hash
     * @param string $algo
     * @return string
     */
    public function preHash($directive = 'script-src', $hash = '', $algo = 'sha256')
    {
        $ruleKeys = \array_keys($this->policies);
        if (\in_array($directive, $ruleKeys)) {
            $this->policies[$directive]['hashes'] []= [
                $algo => \strtr($hash, '+/', '-_')
            ];
        }
        return $this;
    }
    
    /**
     * PSR-7 header injection
     * 
     * @param \Psr\Http\Message\MessageInterface $message
     * @param bool $legacy
     * @return \Psr\Http\Message\MessageInterface
     */
    function injectCSPHeader(MessageInterface $message, $legacy = false)
    {
        if ($this->needsCompile) {
            $this->compile();
        }
        foreach ($this->getHeaderKeys($legacy) as $key) {
            $message = $message->withAddedHeader($key, $this->compiled);
        }
        return $message;
    }
    
    /**
     * Add a new nonce to the existing CSP
     * 
     * @param string $directive
     * @param string $nonce (if NULL, will be generated)
     */
    public function nonce($directive = 'script-src', $nonce = null)
    {
        $ruleKeys = \array_keys($this->policies);
        if (\in_array($directive, $ruleKeys)) {
            if (empty($nonce)) {
                $nonce = \base64_encode(
                    \random_bytes(18)
                );
            }
            $this->policies[$directive]['nonces'] []= $nonce;
            return $nonce;
        }
    }
    
    /**
     * Save CSP to a snippet file
     * 
     * @param string $outputFile Output file name
     * @param string $format Which format are we saving in?
     * @return int|boolean
     */
    public function saveSnippet($outputFile, $format = self::FORMAT_NGINX)
    {
        if ($this->needsCompile) {
            $this->compile();
        }
        
        // Are we doing a report-only header?
        $which = $this->reportOnly 
            ? 'Content-Security-Policy-Report-Only'
            : 'Content-Security-Policy';
        
        switch ($format) {
            case self::FORMAT_NGINX:
                // In PHP < 7, implode() is faster than concatenation
                $output = \implode('', [
                    'add_header ',
                    $which,
                    ' "',
                        \rtrim($this->compiled, ' '),
                    '";',
                    "\n"
                ]);
                break;
            case self::FORMAT_APACHE:
                $output = \implode('', [
                    'Header add ',
                    $which,
                    ' "',
                        \rtrim($this->compiled, ' '),
                    '";',
                    "\n"
                ]);
                break;
            default:
                throw new \Exception('Unknown format: '.$format);
        }
        return \file_put_contents($outputFile, $output);
    }
    
    /**
     * Send the compiled CSP as a header()
     * 
     * @param boolean $legacy Send legacy headers?
     * 
     * @return boolean
     * @throws \Exception
     */
    public function sendCSPHeader($legacy = true)
    {
        if (\headers_sent()) {
            throw new \Exception('Headers already sent!');
        }
        if ($this->needsCompile) {
            $this->compile();
        }
        foreach ($this->getHeaderKeys($legacy) as $key) {
            \header($key.': '.$this->compiled);
        }
        return true;
    }
    
    /**
     * Set a directive
     * 
     * @param string $key
     * @param mixed $value
     * 
     * @return CSPBuilder
     */
    public function setDirective($key, $value = null)
    {
        $this->policies[$key] = $value;
        return $this;
    }
    
    /**
     * Compile a subgroup into a policy string
     * 
     * @param string $directive
     * @param mixed $policies
     * 
     * @return string
     */
    protected function compileSubgroup($directive, $policies = null)
    {
        if ($policies === '*') {
            // Don't even waste the overhead adding this to the header
            return '';
        } elseif (empty($policies)) {
            return $directive." 'none'; ";
        }
        $ret = $directive.' ';
        if (!empty($policies['self'])) {
            $ret .= "'self' ";
        }
        
        if (!empty($policies['allow'])) {
            foreach ($policies['allow'] as $url) {
                $url = \filter_var($url, FILTER_SANITIZE_URL);
                if ($url !== false) {
                    if ($this->supportOldBrowsers) {
                        if (\strpos($url, '://') === false) {
                            if ($this->isHTTPSconnection() || !empty($this->policies['upgrade-insecure-requests'])) {
                                // We only want HTTPS connections here.
                                $ret .= 'https://'.$url.' ';
                            } else {
                                $ret .= 'https://'.$url.' http://'.$url.' ';
                            }
                        }
                    }
                    if ($this->isHTTPSconnection() || !empty($this->policies['upgrade-insecure-requests'])) {
                        $ret .= \str_replace('http://', 'https://', $url).' ';
                    } else {
                        $ret .= $url.' ';
                    }
                }
            }
        }
        
        if (!empty($policies['hashes'])) {
            foreach ($policies['hashes'] as $hash) {
                foreach ($hash as $algo => $hashval) {
                    $ret .= \implode('', [
                        "'",
                        \preg_replace('/[^A-Za-z0-9]/', '', $algo),
                        '-',
                        \preg_replace('/[^A-Za-z0-9_\+\.\/=]/', '', $hashval),
                        "' "
                    ]);
                }
            }
        }
        
        if (!empty($policies['nonces'])) {
            foreach ($policies['nonces'] as $nonce) {
                $ret .= \implode('', [
                    "'nonce-",
                    \preg_replace('/[^A-Za-z0-9_\+\.\/=]/', '', $nonce),
                    "' "
                ]);
            }
        }
        
        if (!empty($policies['types'])) {
            foreach ($policies['types'] as $type) {
                $ret .= $type.' ';
            }
        }
        
        if (!empty($policies['unsafe-inline'])) {
            $ret .= "'unsafe-inline' ";
        }
        if (!empty($policies['unsafe-eval'])) {
            $ret .= "'unsafe-eval'";
        }
        if (!empty($policies['data'])) {
            $ret .= "data: ";
        }
        return \rtrim($ret, ' ').'; ';
    }
    
    /**
     * Get an array of header keys to return
     * 
     * @param bool $legacy
     * @return array
     */
    protected function getHeaderKeys($legacy = true)
    {
        // We always want this
        $return = [
            $this->reportOnly 
                ? 'Content-Security-Policy-Report-Only'
                : 'Content-Security-Policy'
        ];
        
        // If we're supporting legacy devices, include these too:
        if ($legacy) {
            $return []= $this->reportOnly 
                ? 'X-Content-Security-Policy-Report-Only'
                : 'X-Content-Security-Policy';
            $return []= $this->reportOnly 
                ? 'X-Webkit-CSP-Report-Only'
                : 'X-Webkit-CSP';
        }
        return $return;
    }
    
    /**
     * Is this user currently connected over HTTPS?
     * 
     * @return bool
     */
    protected function isHTTPSconnection()
    {
        if (!empty($_SERVER['HTTPS'])) {
            return $_SERVER['HTTPS'] !== 'off';
        }
        return false;
    }
}
